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
    #"https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/controld/spam-tlds-folder.json",
    #https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/controld/spam-idns-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/controld/spam-tlds-combined-folder.json",
]

BATCH_SIZE = 200
MAX_RETRIES = 3
CONCURRENCY_LIMIT = 5 
RULE_LIMIT = 10000

EXCLUDED_PROFILES = [
    "793407laxinb",
    "712995laxgov", 
    "789687laxwlw"
]

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
    log.info("💾 State saved to state.json")

def calculate_hash(data: Dict) -> str:
    serialized = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()

# --------------------------------------------------------------------------- #
# 2. Async Clients & Helpers
# --------------------------------------------------------------------------- #

async def _retry_request(request_func):
    for attempt in range(MAX_RETRIES):
        try:
            response = await request_func()
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            if e.response.status_code in [400, 401]:
                raise
            if attempt == MAX_RETRIES - 1:
                log.error(f"❌ API Error: {e.response.text}")
                raise
        except (httpx.ConnectError, httpx.TimeoutException):
            if attempt == MAX_RETRIES - 1:
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

async def get_rule_count(client: httpx.AsyncClient, profile_id: str) -> int:
    try:
        resp = await _retry_request(lambda: client.get(f"{API_BASE}/profiles/{profile_id}/rules"))
        data = resp.json()
        return len(data.get("body", {}).get("rules", []))
    except Exception:
        return 0

async def push_rules(client: httpx.AsyncClient, profile_id, folder_name, folder_id, do, status, hostnames):
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    
    for i, batch in enumerate(batches, 1):
        payload = {
            "do": int(do),
            "status": int(status),
            "group": str(folder_id),
            "hostnames": batch
        }
        
        if i == 1:
            for attempt in range(5):
                try:
                    resp = await client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=payload)
                    resp.raise_for_status()
                    break
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        await asyncio.sleep(1)
                        continue
                    raise e
        else:
            try:
                await _retry_request(lambda: client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=payload))
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 400:
                    log.warning(f"  ⚠️ [{folder_name}] Batch {i} failed. Retrying entries individually...")
                    for h in batch:
                        try:
                            single_payload = {**payload, "hostnames": [h]}
                            await client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=single_payload)
                        except Exception:
                            pass

# --------------------------------------------------------------------------- #
# 3. Main Sync Logic
# --------------------------------------------------------------------------- #

async def sync_single_profile(sem: asyncio.Semaphore, auth_client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict], state: Dict):
    async with sem:
        log.info(f"--- Processing Profile: {profile_id} ---")
        
        current_rules = await get_rule_count(auth_client, profile_id)
        log.info(f"📊 Current Rule Count: {current_rules}/{RULE_LIMIT}")

        current_folders = await list_folders(auth_client, profile_id)
        
        if profile_id not in state:
            state[profile_id] = {}

        for remote in remote_data:
            group_data = remote.get("group", {})
            name = group_data.get("group", "Unnamed Folder").strip()
            
            new_hash = calculate_hash(remote)
            stored_hash = state[profile_id].get(name)
            
            raw_rules = remote.get("rules", [])
            
            if name in current_folders and stored_hash == new_hash:
                log.info(f"⏩ [{name}] No changes. Skipping.")
                continue
            
            if current_rules + len(raw_rules) > RULE_LIMIT:
                log.error(f"❌ [{name}] Sync aborted. Adding {len(raw_rules)} rules exceeds 10k limit.")
                continue

            log.info(f"🔄 [{name}] Update detected. Executing zero-downtime swap...")
            
            # --- Sort rules into action buckets ---
            action_buckets = {}
            for r in raw_rules:
                hostname = r.get("PK")
                if not hostname:
                    continue
                
                # Use rule's specific action; default to block (0) and active (1)
                r_action = r.get("action", {})
                r_do = int(r_action.get("do", 0)) 
                r_status = int(r_action.get("status", 1))
                
                key = (r_do, r_status)
                if key not in action_buckets:
                    action_buckets[key] = []
                action_buckets[key].append(hostname)

            temp_name = f"{name}_tmp"

            try:
                # 1. Create Temp Group (Omit 'do' and 'status' to avoid global folder rule)
                await _retry_request(lambda: auth_client.post(
                    f"{API_BASE}/profiles/{profile_id}/groups", 
                    json={"name": temp_name}
                ))
                
                updated_folders = await list_folders(auth_client, profile_id)
                new_id = updated_folders.get(temp_name)
                
                if new_id:
                    # 2. Push rules concurrently via action buckets
                    push_tasks = [
                        push_rules(auth_client, profile_id, temp_name, new_id, b_do, b_status, hostnames)
                        for (b_do, b_status), hostnames in action_buckets.items()
                    ]
                    await asyncio.gather(*push_tasks)
                    
                    # 3. Delete Old Group
                    if name in current_folders:
                        await _retry_request(lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{current_folders[name]}"))

                    # 4. Rename Temp Group to Original Name
                    await _retry_request(lambda: auth_client.put(
                        f"{API_BASE}/profiles/{profile_id}/groups/{new_id}",
                        json={"name": name}
                    ))

                    state[profile_id][name] = new_hash
                    log.info(f"✅ [{name}] Synced with {len(action_buckets)} action types.")
                else:
                    log.error(f"❌ [{name}] Failed to verify temp folder creation.")

            except Exception as e:
                log.error(f"❌ [{name}] Sync failed: {e}")
            finally:
                # Cleanup: If the sync failed midway, attempt to delete the orphaned temp folder
                try:
                    cleanup_folders = await list_folders(auth_client, profile_id)
                    if temp_name in cleanup_folders:
                        log.info(f"🧹 Cleaning up orphaned temp folder: {temp_name}")
                        await _retry_request(lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{cleanup_folders[temp_name]}"))
                except Exception:
                    pass

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var.")
        return

    state = load_state()

    try:
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60) as auth_client, \
                   httpx.AsyncClient(timeout=60) as gh_client:
            
            log.info("📥 Fetching blocklists...")
            gh_tasks = [fetch_gh_json(gh_client, url) for url in FOLDER_URLS]
            results = await asyncio.gather(*gh_tasks, return_exceptions=True)
            valid_remote_data = [r for r in results if isinstance(r, dict)]

            if not valid_remote_data:
                log.warning("No valid blocklist data found.")
                return

            pids = [p for p in await get_all_profiles(auth_client) if p not in EXCLUDED_PROFILES]
            sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
            
            await asyncio.gather(*(sync_single_profile(sem, auth_client, pid, valid_remote_data, state) for pid in pids))
    
    finally:
        save_state(state)

if __name__ == "__main__":
    asyncio.run(main_async())
