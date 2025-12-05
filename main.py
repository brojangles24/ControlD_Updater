#!/usr/bin/env python3
"""
Control D Sync (Async Genius Edition)
-------------------------------------
1. Async/Await for maximum speed.
2. Parallels profile syncing.
3. Smart Fallback for duplicate rules (Batch -> 1-by-1).
4. Auto-discovery & Exclusion logic.
"""

import os
import logging
import asyncio
from typing import Dict, List, Any, Set

import httpx
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --------------------------------------------------------------------------- #
# 0. Config
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("control-d-sync")

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")

# USER DEFINED URLS
FOLDER_URLS = [
    # --- Aggressive Security ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-tlds-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-idns-folder.json",
    
    # --- Native Trackers ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-amazon-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-apple-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-microsoft-folder.json",
]

BATCH_SIZE = 200
MAX_RETRIES = 3
# Limit concurrent operations to prevent API abuse/rate limits
CONCURRENCY_LIMIT = 5 

# --------------------------------------------------------------------------- #
# 1. Async Clients & Helpers
# --------------------------------------------------------------------------- #

async def _retry_request(request_func):
    """Async retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = await request_func()
            # If 400 (Bad Request), raise immediately so business logic handles it
            if response.status_code == 400:
                response.raise_for_status()
            
            response.raise_for_status()
            return response
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            # If it's a 400, stop retrying and let the caller handle it (Smart Fallback)
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 400:
                raise
                
            if attempt == MAX_RETRIES - 1:
                if hasattr(e, 'response') and e.response is not None:
                    log.error(f"❌ API Error: {e.response.text}")
                raise
            await asyncio.sleep(1 * (2 ** attempt))

async def fetch_gh_json(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    resp = await client.get(url)
    resp.raise_for_status()
    return resp.json()

async def get_all_profiles(client: httpx.AsyncClient) -> List[str]:
    try:
        resp = await _retry_request(lambda: client.get(f"{API_BASE}/profiles"))
        data = resp.json()
        profiles = [p["PK"] for p in data.get("body", {}).get("profiles", [])]
        log.info(f"🔎 Auto-discovered {len(profiles)} profiles.")
        return profiles
    except Exception as e:
        log.error(f"Failed to auto-discover profiles: {e}")
        return []

async def list_folders(client: httpx.AsyncClient, profile_id: str) -> Dict[str, str]:
    try:
        resp = await _retry_request(lambda: client.get(f"{API_BASE}/profiles/{profile_id}/groups"))
        data = resp.json()
        return {g["group"].strip(): g["PK"] for g in data.get("body", {}).get("groups", [])}
    except Exception:
        return {}

# --------------------------------------------------------------------------- #
# 2. Async Logic
# --------------------------------------------------------------------------- #

async def push_rules(client: httpx.AsyncClient, profile_id, folder_name, folder_id, do, status, hostnames):
    existing_rules = set()
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    total = len(batches)
    
    for i, batch in enumerate(batches, 1):
        to_push = [h for h in batch if h not in existing_rules]
        if not to_push: continue

        data = {"do": str(do), "status": str(status), "group": str(folder_id)}
        batch_data = data.copy()
        for j, h in enumerate(to_push):
            batch_data[f"hostnames[{j}]"] = h
            
        try:
            # 1. Try pushing the whole batch
            await _retry_request(lambda: client.post(
                f"{API_BASE}/profiles/{profile_id}/rules", 
                data=batch_data, 
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ))
            log.info(f"   └─ [{folder_name}] Batch {i}/{total}: Pushed {len(to_push)} rules.")
            existing_rules.update(to_push)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                # 2. BATCH FAILED - Smart Fallback (1-by-1)
                log.warning(f"   ⚠️ [{folder_name}] Batch {i}/{total} hit conflict. Retrying individually...")
                success_count = 0
                
                for h in to_push:
                    single_data = data.copy()
                    single_data["hostnames[0]"] = h
                    try:
                        await client.post(
                            f"{API_BASE}/profiles/{profile_id}/rules", 
                            data=single_data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"}
                        )
                        success_count += 1
                        existing_rules.add(h)
                    except Exception:
                        # Ignore duplicates on individual push
                        pass
                log.info(f"   └─ [{folder_name}] Recovered: {success_count}/{len(to_push)} rules.")
            else:
                log.error(f"   ❌ [{folder_name}] Batch {i} failed: {e}")

async def sync_single_profile(sem: asyncio.Semaphore, auth_client: httpx.AsyncClient, gh_client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict]):
    async with sem:
        log.info(f"--- Syncing Profile: {profile_id} ---")
        
        # Get Current Folders
        current_folders = await list_folders(auth_client, profile_id)

        for remote in remote_data:
            name = remote["group"]["group"].strip()
            do_action = remote["group"]["action"]["do"]
            status = remote["group"]["action"]["status"]
            rules = [r["PK"] for r in remote.get("rules", []) if r.get("PK")]

            # Nuclear Delete
            if name in current_folders:
                log.info(f"🗑️  [{profile_id}] Deleting '{name}'...")
                try:
                    await _retry_request(lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{current_folders[name]}"))
                except Exception as e:
                    log.error(f"Failed to delete {name}: {e}")

            # Create New
            log.info(f"✨ [{profile_id}] Creating '{name}'...")
            try:
                await _retry_request(lambda: auth_client.post(
                    f"{API_BASE}/profiles/{profile_id}/groups", 
                    data={"name": name, "do": do_action, "status": status}
                ))
                
                # Wait briefly for consistency
                await asyncio.sleep(1)
                
                new_folders = await list_folders(auth_client, profile_id)
                new_id = new_folders.get(name)
                
                if new_id:
                    await push_rules(auth_client, profile_id, name, new_id, do_action, status, rules)
                else:
                    log.error(f"Could not find new folder ID for {name}")

            except Exception as e:
                log.error(f"Failed to create/sync {name}: {e}")

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var.")
        return

    # --- CONFIG: EXCLUSIONS ---
    EXCLUDED_PROFILES = ["780037lax6zo"]
    # --------------------------

    # Initialize Clients
    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60) as auth_client, \
               httpx.AsyncClient(timeout=60) as gh_client:
        
        # 1. Fetch Remote Blocklists (Parallel)
        log.info("📥 Fetching blocklists from GitHub...")
        gh_tasks = [fetch_gh_json(gh_client, url) for url in FOLDER_URLS]
        remote_data = await asyncio.gather(*gh_tasks, return_exceptions=True)
        valid_remote_data = [r for r in remote_data if isinstance(r, dict)]

        if not valid_remote_data:
            log.error("No valid blocklists fetched.")
            return

        # 2. Discover Profiles
        env_profiles = os.getenv("PROFILE", "").strip()
        if env_profiles:
            pids = [p.strip() for p in env_profiles.split(",") if p.strip()]
        else:
            pids = await get_all_profiles(auth_client)

        # 3. Apply Exclusions
        pids = [p for p in pids if p not in EXCLUDED_PROFILES]

        if not pids:
            log.error("No profiles found to sync.")
            return

        # 4. Sync Profiles (Concurrent with Semaphore)
        sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
        tasks = [sync_single_profile(sem, auth_client, gh_client, pid, valid_remote_data) for pid in pids]
        
        await asyncio.gather(*tasks)

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
