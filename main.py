#!/usr/bin/env python3
"""
Control D Sync (Async + Auto-Discovery)
---------------------------------------
A high-performance helper that keeps ALL your Control D profiles in sync 
with aggressive remote block-lists.

Features:
1. Auto-discovers all profiles (if none specified in .env).
2. Uses asyncio for parallel fetching and rule pushing.
3. Includes Badware Hoster & Spam TLDs.
4. Robust rate limiting to prevent API errors.
"""

import os
import logging
import asyncio
from typing import Dict, List, Optional, Any, Set

import httpx
from tqdm.asyncio import tqdm
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# 0. Bootstrap
# --------------------------------------------------------------------------- #
load_dotenv()

# Configure logging to exclude httpx noise
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("control-d-sync")

# --------------------------------------------------------------------------- #
# 1. Constants
# --------------------------------------------------------------------------- #
API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")

# If PROFILE is set in .env, use those. If empty, script will auto-discover ALL.
_env_profiles = os.getenv("PROFILE", "")
PROFILE_IDS = [p.strip() for p in _env_profiles.split(",") if p.strip()]

FOLDER_URLS = [
    # --- Aggressive Security Layers (Requested) ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-tlds-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-idns-folder.json",
    
    # --- Native Trackers & Privacy ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-amazon-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-microsoft-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-tiktok-aggressive-folder.json",
    
    # --- Maintenance & Allow Lists ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/referral-allow-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/ultimate-known_issues-allow-folder.json",
]

BATCH_SIZE = 500
MAX_RETRIES = 3
RETRY_DELAY = 1.0
CONCURRENCY_LIMIT = 5  # Limit concurrent API requests to avoid 429 errors

# --------------------------------------------------------------------------- #
# 2. Async Clients & Helpers
# --------------------------------------------------------------------------- #

async def _api_request(
    client: httpx.AsyncClient, 
    method: str, 
    endpoint: str, 
    **kwargs
) -> httpx.Response:
    """Generic async API wrapper with retries."""
    url = f"{API_BASE}{endpoint}"
    for attempt in range(MAX_RETRIES):
        try:
            response = await client.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            if attempt == MAX_RETRIES - 1:
                if hasattr(e, 'response') and e.response is not None:
                    log.error(f"Final Fail Content: {e.response.text}")
                raise
            
            wait_time = RETRY_DELAY * (2 ** attempt)
            log.warning(f"Retry {attempt + 1}/{MAX_RETRIES} for {endpoint} in {wait_time}s...")
            await asyncio.sleep(wait_time)
    raise httpx.HTTPError("Max retries exceeded")

async def fetch_github_json(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    """Fetch JSON from GitHub."""
    resp = await client.get(url)
    resp.raise_for_status()
    return resp.json()

async def fetch_all_profile_ids(client: httpx.AsyncClient) -> List[str]:
    """Auto-discover all profile IDs from the account."""
    try:
        log.info("Auto-discovering profiles...")
        resp = await _api_request(client, "GET", "/profiles")
        profiles = resp.json().get("body", {}).get("profiles", [])
        ids = [p["PK"] for p in profiles if p.get("PK")]
        log.info(f"Found {len(ids)} profiles: {ids}")
        return ids
    except Exception as e:
        log.error(f"Failed to auto-discover profiles: {e}")
        return []

# --------------------------------------------------------------------------- #
# 3. Core Logic
# --------------------------------------------------------------------------- #

async def list_existing_folders(client: httpx.AsyncClient, profile_id: str) -> Dict[str, str]:
    """Return folder-name -> folder-id mapping."""
    try:
        resp = await _api_request(client, "GET", f"/profiles/{profile_id}/groups")
        folders = resp.json().get("body", {}).get("groups", [])
        return {
            f["group"].strip(): f["PK"]
            for f in folders
            if f.get("group") and f.get("PK")
        }
    except Exception as e:
        log.error(f"Failed to list folders: {e}")
        return {}

async def get_folder_rules(client: httpx.AsyncClient, profile_id: str, folder_id: Optional[str] = None) -> Set[str]:
    """Fetch rules for a specific folder (or root if folder_id is None)."""
    endpoint = f"/profiles/{profile_id}/rules"
    if folder_id:
        endpoint += f"/{folder_id}"
    
    try:
        resp = await _api_request(client, "GET", endpoint)
        rules = resp.json().get("body", {}).get("rules", [])
        return {r["PK"] for r in rules if r.get("PK")}
    except httpx.HTTPError:
        return set()

async def get_all_existing_rules(client: httpx.AsyncClient, profile_id: str) -> Set[str]:
    """Get all existing rules concurrently."""
    all_rules = set()
    
    # 1. Get Root Rules
    root_rules = await get_folder_rules(client, profile_id, None)
    all_rules.update(root_rules)
    
    # 2. Get all folders
    folders = await list_existing_folders(client, profile_id)
    
    # 3. Fetch all folder rules in parallel
    tasks = [get_folder_rules(client, profile_id, fid) for fid in folders.values()]
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                all_rules.update(res)
                
    log.info(f"Total existing rules across profile: {len(all_rules)}")
    return all_rules

async def delete_folder(client: httpx.AsyncClient, profile_id: str, name: str, folder_id: str):
    await _api_request(client, "DELETE", f"/profiles/{profile_id}/groups/{folder_id}")
    log.info(f"Deleted old folder: {name}")

async def create_folder(client: httpx.AsyncClient, profile_id: str, name: str, do: int, status: int) -> Optional[str]:
    try:
        await _api_request(
            client, 
            "POST", 
            f"/profiles/{profile_id}/groups",
            json={"name": name, "do": do, "status": status}
        )
        # Brief pause to allow DB propagation
        await asyncio.sleep(0.5)
        folders = await list_existing_folders(client, profile_id)
        return folders.get(name.strip())
    except Exception as e:
        log.error(f"Failed to create folder '{name}': {e}")
        return None

async def push_batch(client: httpx.AsyncClient, profile_id: str, data: Dict) -> bool:
    """Helper to push a single batch."""
    try:
        await _api_request(
            client, 
            "POST", 
            f"/profiles/{profile_id}/rules", 
            data=data, 
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        return True
    except Exception as e:
        log.error(f"Batch failed: {e}")
        return False

async def process_folder_sync(
    client: httpx.AsyncClient, 
    profile_id: str, 
    folder_data: Dict, 
    existing_rules: Set[str],
    semaphore: asyncio.Semaphore
) -> bool:
    """Handles the lifecycle of a single folder import."""
    
    grp = folder_data["group"]
    name = grp["group"].strip()
    do = grp["action"]["do"]
    status = grp["action"]["status"]
    hostnames = [r["PK"] for r in folder_data.get("rules", []) if r.get("PK")]
    
    # 1. Create Folder
    async with semaphore:
        folder_id = await create_folder(client, profile_id, name, do, status)
    
    if not folder_id:
        return False

    # 2. Filter Duplicates
    filtered = [h for h in hostnames if h not in existing_rules]
    
    if not filtered:
        log.info(f"[{name}] Sync complete (No new rules)")
        return True

    # 3. Push Batches
    batches = [filtered[i:i + BATCH_SIZE] for i in range(0, len(filtered), BATCH_SIZE)]
    success_count = 0
    
    async for batch in tqdm(batches, desc=f"Syncing {name}", unit="batch", leave=False):
        data = {
            "do": str(do), 
            "status": str(status), 
            "group": str(folder_id)
        }
        for j, h in enumerate(batch):
            data[f"hostnames[{j}]"] = h
        
        async with semaphore:
            if await push_batch(client, profile_id, data):
                success_count += 1
                existing_rules.update(batch)

    return success_count == len(batches)

# --------------------------------------------------------------------------- #
# 4. Main Workflow
# --------------------------------------------------------------------------- #

async def sync_profile(client: httpx.AsyncClient, profile_id: str):
    log.info(f"--- Starting Sync for Profile: {profile_id} ---")
    
    # A. Fetch all GitHub JSONs
    log.info("Fetching remote blocklists...")
    gh_tasks = [fetch_github_json(client, url) for url in FOLDER_URLS]
    folder_data_list = await asyncio.gather(*gh_tasks, return_exceptions=True)
    
    valid_data = [res for res in folder_data_list if isinstance(res, dict)]
    if not valid_data:
        log.error("No valid blocklist data found.")
        return

    # B. Clean up old folders
    existing_folders = await list_existing_folders(client, profile_id)
    delete_tasks = []
    for data in valid_data:
        name = data["group"]["group"].strip()
        if name in existing_folders:
            delete_tasks.append(delete_folder(client, profile_id, name, existing_folders[name]))
    
    if delete_tasks:
        await asyncio.gather(*delete_tasks)

    # C. Build Exclusion List (Existing Rules)
    log.info("Building existing rule index...")
    existing_rules = await get_all_existing_rules(client, profile_id)

    # D. Create and Push
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
    sync_tasks = [
        process_folder_sync(client, profile_id, data, existing_rules, sem)
        for data in valid_data
    ]
    
    results = await asyncio.gather(*sync_tasks)
    success = sum(1 for r in results if r)
    log.info(f"Profile {profile_id} finished: {success}/{len(valid_data)} lists synced.")

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN in .env")
        return

    # Create one client session for the whole run
    async with httpx.AsyncClient(timeout=30, headers={"Authorization": f"Bearer {TOKEN}"}) as client:
        # Determine targets
        if PROFILE_IDS:
            target_profiles = PROFILE_IDS
            log.info(f"Targeting {len(target_profiles)} specific profiles from .env")
        else:
            target_profiles = await fetch_all_profile_ids(client)
            if not target_profiles:
                log.error("No profiles found on account!")
                return

        for pid in target_profiles:
            await sync_profile(client, pid)

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        log.info("Sync interrupted by user.")

if __name__ == "__main__":
    main()
