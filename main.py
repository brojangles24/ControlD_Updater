#!/usr/bin/env python3
"""
Control D Sync (Stateful Edition)
---------------------------------
1. Fetches Remote Blocklists.
2. Calculates SHA256 Hash of the content.
3. Checks local 'state.json' database.
4. SKIPS sync if hash matches (Zero API calls to ControlD).
5. Performs Nuclear Sync only if content changed.
"""

import os
import json
import logging
import asyncio
import hashlib
from typing import Dict, List, Any

import httpx

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
STATE_FILE = "state.json"

FOLDER_URLS = [
    #https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-tlds-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-idns-folder.json",
    #"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-amazon-folder.json",
    #"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-apple-folder.json",
    #"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-microsoft-folder.json",
]

BATCH_SIZE = 200
MAX_RETRIES = 3
CONCURRENCY_LIMIT = 5 

# --------------------------------------------------------------------------- #
# 1. State Management
# --------------------------------------------------------------------------- #

def load_state() -> Dict[str, Dict[str, str]]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_state(state: Dict):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2, sort_keys=True)

def calculate_hash(data: Dict) -> str:
    """Creates a unique fingerprint for the JSON data."""
    # Sort keys to ensure consistency
    serialized = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()

# --------------------------------------------------------------------------- #
# 2. Async Clients & Helpers
# --------------------------------------------------------------------------- #

async def _retry_request(request_func):
    for attempt in range(MAX_RETRIES):
        try:
            response = await request_func()
            if response.status_code == 400:
                response.raise_for_status()
            response.raise_for_status()
            return response
        except (httpx.HTTPError, httpx.TimeoutException) as e:
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
        return [p["PK"] for p in data.get("body", {}).get("profiles", [])]
    except Exception:
        return []

async def list_folders(client: httpx.AsyncClient, profile_id: str) -> Dict[str, str]:
    try:
        resp = await _retry_request(lambda: client.get(f"{API_BASE}/profiles/{profile_id}/groups"))
        data = resp.json()
        return {g["group"].strip(): g["PK"] for g in data.get("body", {}).get("groups", [])}
    except Exception:
        return {}

async def push_rules(client: httpx.AsyncClient, profile_id, folder_name, folder_id, do, status, hostnames):
    existing_rules = set()
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    
    for i, batch in enumerate(batches, 1):
        to_push = [h for h in batch if h not in existing_rules]
        if not to_push: continue

        data = {"do": str(do), "status": str(status), "group": str(folder_id)}
        batch_data = data.copy()
        for j, h in enumerate(to_push):
            batch_data[f"hostnames[{j}]"] = h
            
        try:
            await _retry_request(lambda: client.post(
                f"{API_BASE}/profiles/{profile_id}/rules", 
                data=batch_data, 
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ))
            existing_rules.update(to_push)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                log.warning(f"   ⚠️ [{folder_name}] Batch {i} conflict. Retrying individually...")
                for h in to_push:
                    single_data = data.copy()
                    single_data["hostnames[0]"] = h
                    try:
                        await client.post(f"{API_BASE}/profiles/{profile_id}/rules", data=single_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
                        existing_rules.add(h)
                    except Exception:
                        pass

# --------------------------------------------------------------------------- #
# 3. Main Sync Logic
# --------------------------------------------------------------------------- #

async def sync_single_profile(sem: asyncio.Semaphore, auth_client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict], state: Dict):
    async with sem:
        log.info(f"--- Processing Profile: {profile_id} ---")
        current_folders = await list_folders(auth_client, profile_id)
        
        # Ensure state entry exists
        if profile_id not in state:
            state[profile_id] = {}

        for remote in remote_data:
            name = remote["group"]["group"].strip()
            
            # 1. HASH CHECK
            new_hash = calculate_hash(remote)
            stored_hash = state[profile_id].get(name)
            
            # If folder exists remotely AND hash matches, SKIP.
            if name in current_folders and stored_hash == new_hash:
                log.info(f"⏩ [{name}] No changes detected. Skipping.")
                continue
            
            # If we are here, either it's a new folder, or the hash changed.
            log.info(f"🔄 [{name}] Update detected. Syncing...")
            
            do_action = remote["group"]["action"]["do"]
            status = remote["group"]["action"]["status"]
            rules = [r["PK"] for r in remote.get("rules", []) if r.get("PK")]

            # Nuclear Delete
            if name in current_folders:
                try:
                    await _retry_request(lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{current_folders[name]}"))
                except Exception:
                    pass

            # Create New
            try:
                await _retry_request(lambda: auth_client.post(
                    f"{API_BASE}/profiles/{profile_id}/groups", 
                    data={"name": name, "do": do_action, "status": status}
                ))
                await asyncio.sleep(1)
                new_folders = await list_folders(auth_client, profile_id)
                new_id = new_folders.get(name)
                
                if new_id:
                    await push_rules(auth_client, profile_id, name, new_id, do_action, status, rules)
                    # UPDATE STATE on success
                    state[profile_id][name] = new_hash
                    log.info(f"✅ [{name}] Synced & State Updated.")
                else:
                    log.error(f"❌ [{name}] Failed to verify folder creation.")

            except Exception as e:
                log.error(f"❌ [{name}] Sync failed: {e}")

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var.")
        return

    EXCLUDED_PROFILES = ["780037lax6zo"]
    
    # Load previous state
    state = load_state()

    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60) as auth_client, \
               httpx.AsyncClient(timeout=60) as gh_client:
        
        log.info("📥 Fetching blocklists...")
        gh_tasks = [fetch_gh_json(gh_client, url) for url in FOLDER_URLS]
        remote_data = await asyncio.gather(*gh_tasks, return_exceptions=True)
        valid_remote_data = [r for r in remote_data if isinstance(r, dict)]

        if not valid_remote_data:
            return

        pids = await get_all_profiles(auth_client)
        pids = [p for p in pids if p not in EXCLUDED_PROFILES]

        sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
        # We pass the 'state' dict to all tasks. They modify it in place.
        # Since we run on a single thread event loop (Python AsyncIO), 
        # dictionary operations are thread-safe enough for this use case without locks.
        tasks = [sync_single_profile(sem, auth_client, pid, valid_remote_data, state) for pid in pids]
        
        await asyncio.gather(*tasks)
    
    # Save updated state to file
    save_state(state)
    log.info("💾 State saved to state.json")

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
