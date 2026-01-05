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
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-idns-folder.json",
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
            # Don't retry 400s (Bad Request) or 401s (Unauthorized)
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

async def push_rules(client: httpx.AsyncClient, profile_id, folder_name, folder_id, do, status, hostnames):
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    
    for i, batch in enumerate(batches, 1):
        data = {"do": str(do), "status": str(status), "group": str(folder_id)}
        for j, h in enumerate(batch):
            data[f"hostnames[{j}]"] = h
            
        try:
            await _retry_request(lambda: client.post(
                f"{API_BASE}/profiles/{profile_id}/rules", 
                data=data, 
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            ))
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                log.warning(f"  ⚠️ [{folder_name}] Batch {i} failed. Retrying entries individually...")
                for h in batch:
                    try:
                        single_data = {"do": str(do), "status": str(status), "group": str(folder_id), "hostnames[0]": h}
                        await client.post(f"{API_BASE}/profiles/{profile_id}/rules", data=single_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
                    except Exception:
                        pass

# --------------------------------------------------------------------------- #
# 3. Main Sync Logic
# --------------------------------------------------------------------------- #

async def sync_single_profile(sem: asyncio.Semaphore, auth_client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict], state: Dict):
    async with sem:
        log.info(f"--- Processing Profile: {profile_id} ---")
        current_folders = await list_folders(auth_client, profile_id)
        
        if profile_id not in state:
            state[profile_id] = {}

        for remote in remote_data:
            name = remote["group"]["group"].strip()
            new_hash = calculate_hash(remote)
            stored_hash = state[profile_id].get(name)
            
            if name in current_folders and stored_hash == new_hash:
                log.info(f"⏩ [{name}] No changes. Skipping.")
                continue
            
            log.info(f"🔄 [{name}] Update detected.")
            
            do_action = remote["group"]["action"]["do"]
            status = remote["group"]["action"]["status"]
            rules = [r["PK"] for r in remote.get("rules", []) if r.get("PK")]

            # Remove old group if it exists
            if name in current_folders:
                try:
                    await _retry_request(lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{current_folders[name]}"))
                except Exception:
                    pass

            # Create New Group & Rules
            try:
                await _retry_request(lambda: auth_client.post(
                    f"{API_BASE}/profiles/{profile_id}/groups", 
                    data={"name": name, "do": do_action, "status": status}
                ))
                await asyncio.sleep(1) # API propagation delay
                
                updated_folders = await list_folders(auth_client, profile_id)
                new_id = updated_folders.get(name)
                
                if new_id:
                    await push_rules(auth_client, profile_id, name, new_id, do_action, status, rules)
                    state[profile_id][name] = new_hash
                    log.info(f"✅ [{name}] Synced.")
                else:
                    log.error(f"❌ [{name}] Failed to verify creation.")

            except Exception as e:
                log.error(f"❌ [{name}] Sync failed: {e}")

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var.")
        return

    EXCLUDED_PROFILES = ["793407laxinb"]
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
