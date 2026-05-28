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
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/controld/spam-tlds-combined-folder.json",
]

BATCH_SIZE = 200
MAX_RETRIES = 3
CONCURRENCY_LIMIT = 5 
RULE_LIMIT = 10000

# Explicit mapping of public pseudonyms to incoming environment variables
PROFILE_MAPPING = {
    "guest": os.getenv("GUEST"),
    "iot": os.getenv("IOT"),
    "main": os.getenv("MAIN"),
    "user_i": os.getenv("USER_I"),
    "user_k": os.getenv("USER_K"),
}

# TOGGLE EXCLUSIONS HERE: Simply add or remove strings from this list
EXCLUDED_PROFILES = ["iot", "guest", "user_k"]

# Resolve chosen pseudonyms down to the actual hidden IDs
EXCLUDED_IDS = {
    PROFILE_MAPPING[p] for p in EXCLUDED_PROFILES if PROFILE_MAPPING.get(p)
}

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
    tmp_file = f"{STATE_FILE}.tmp"
    try:
        with open(tmp_file, 'w') as f:
            json.dump(state, f, indent=2, sort_keys=True)
        os.replace(tmp_file, STATE_FILE)
        log.info("💾 State saved securely to state.json")
    except Exception as e:
        log.error(f"❌ Failed to save state safely: {e}")
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

def calculate_hash(data: Dict) -> str:
    serialized = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()

# --------------------------------------------------------------------------- #
# 2. Async Clients & Helpers
# --------------------------------------------------------------------------- #

async def _retry_request(sem: asyncio.Semaphore, request_func):
    async with sem:
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

async def get_all_profiles(sem: asyncio.Semaphore, client: httpx.AsyncClient) -> List[str]:
    try:
        resp = await _retry_request(sem, lambda: client.get(f"{API_BASE}/profiles"))
        data = resp.json()
        return [p["PK"] for p in data.get("body", {}).get("profiles", [])]
    except Exception:
        return []

async def list_folders(sem: asyncio.Semaphore, client: httpx.AsyncClient, profile_id: str) -> Dict[str, str]:
    try:
        resp = await _retry_request(sem, lambda: client.get(f"{API_BASE}/profiles/{profile_id}/groups"))
        data = resp.json()
        return {g["group"].strip(): g["PK"] for g in data.get("body", {}).get("groups", [])}
    except Exception:
        return {}

async def get_rule_count(sem: asyncio.Semaphore, client: httpx.AsyncClient, profile_id: str) -> int:
    try:
        resp = await _retry_request(sem, lambda: client.get(f"{API_BASE}/profiles/{profile_id}/rules"))
        data = resp.json()
        return len(data.get("body", {}).get("rules", []))
    except Exception:
        return 0

async def push_rules(api_sem: asyncio.Semaphore, client: httpx.AsyncClient, profile_id: str, folder_name: str, folder_id: str, do: int, status: int, hostnames: List[str]):
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    
    async def send_batch(batch: List[str], is_first: bool):
        payload = {
            "do": int(do),
            "status": int(status),
            "group": str(folder_id),
            "hostnames": batch
        }
        if is_first:
            for attempt in range(5):
                try:
                    async with api_sem:
                        resp = await client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=payload)
                    resp.raise_for_status()
                    return
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        await asyncio.sleep(1)
                        continue
                    raise e
        else:
            try:
                await _retry_request(api_sem, lambda: client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=payload))
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 400:
                    log.warning(f"⚠️ [{folder_name}] Batch failed. Retrying entries individually...")
                    fallback_tasks = []
                    for h in batch:
                        single_payload = {**payload, "hostnames": [h]}
                        async def send_single(p):
                            async with api_sem:
                                try:
                                    await client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=p)
                                except Exception as ex:
                                    log.debug(f"Failed to push single hostname {h}: {ex}")
                        fallback_tasks.append(send_single(single_payload))
                    await asyncio.gather(*fallback_tasks)

    if not batches:
        return

    await send_batch(batches[0], is_first=True)

    if len(batches) > 1:
        tasks = [send_batch(b, is_first=False) for b in batches[1:]]
        await asyncio.gather(*tasks)

# --------------------------------------------------------------------------- #
# 3. Main Sync Logic
# --------------------------------------------------------------------------- #

async def sync_single_profile(profile_sem: asyncio.Semaphore, api_sem: asyncio.Semaphore, auth_client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict], state: Dict):
    async with profile_sem:
        log.info(f"--- Processing Profile: {profile_id} ---")
        
        current_rules = await get_rule_count(api_sem, auth_client, profile_id)
        log.info(f"📊 Current Rule Count: {current_rules}/{RULE_LIMIT}")

        current_folders = await list_folders(api_sem, auth_client, profile_id)
        
        if profile_id not in state:
            state[profile_id] = {}

        for remote_item in remote_data:
            name = remote_item["name"]
            new_hash = remote_item["hash"]
            rule_count = remote_item["rule_count"]
            action_buckets = remote_item["action_buckets"]
            
            if name in current_folders and state[profile_id].get(name) == new_hash:
                log.info(f"⏩ [{name}] No changes. Skipping.")
                continue
            
            if current_rules + rule_count > RULE_LIMIT:
                log.error(f"❌ [{name}] Sync aborted. Adding {rule_count} rules exceeds 10k limit.")
                continue

            log.info(f"🔄 [{name}] Update detected. Executing zero-downtime swap...")
            temp_name = f"{name}_tmp"

            try:
                # 1. Create Temp Group
                await _retry_request(api_sem, lambda: auth_client.post(
                    f"{API_BASE}/profiles/{profile_id}/groups", 
                    json={"name": temp_name}
                ))
                
                updated_folders = await list_folders(api_sem, auth_client, profile_id)
                new_id = updated_folders.get(temp_name)
                
                if new_id:
                    # 2. Push rules concurrently via action buckets
                    push_tasks = [
                        push_rules(api_sem, auth_client, profile_id, temp_name, new_id, b_do, b_status, hostnames)
                        for (b_do, b_status), hostnames in action_buckets.items()
                    ]
                    await asyncio.gather(*push_tasks)
                    
                    # 3. Delete Old Group
                    if name in current_folders:
                        await _retry_request(api_sem, lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{current_folders[name]}"))

                    # 4. Rename Temp Group to Original Name
                    await _retry_request(api_sem, lambda: auth_client.put(
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
                try:
                    cleanup_folders = await list_folders(api_sem, auth_client, profile_id)
                    if temp_name in cleanup_folders:
                        log.info(f"🧹 Cleaning up orphaned temp folder: {temp_name}")
                        await _retry_request(api_sem, lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{cleanup_folders[temp_name]}"))
                except Exception:
                    pass

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var. Execution stopped.")
        return

    state = load_state()

    try:
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60, http2=True) as auth_client, \
                   httpx.AsyncClient(timeout=60, http2=True) as gh_client:
            
            api_sem = asyncio.Semaphore(10)
            profile_sem = asyncio.Semaphore(CONCURRENCY_LIMIT)

            log.info("📥 Fetching blocklists...")
            gh_tasks = [fetch_gh_json(gh_client, url) for url in FOLDER_URLS]
            results = await asyncio.gather(*gh_tasks, return_exceptions=True)
            
            valid_remote_data = []
            for r in results:
                if not isinstance(r, dict):
                    continue
                
                raw_rules = r.get("rules", [])
                action_buckets = {}
                for rule in raw_rules:
                    hostname = rule.get("PK")
                    if not hostname:
                        continue
                    r_action = rule.get("action", {})
                    key = (int(r_action.get("do", 0)), int(r_action.get("status", 1)))
                    action_buckets.setdefault(key, []).append(hostname)
                
                valid_remote_data.append({
                    "name": r.get("group", {}).get("group", "Unnamed Folder").strip(),
                    "hash": calculate_hash(r),
                    "rule_count": len(raw_rules),
                    "action_buckets": action_buckets
                })

            if not valid_remote_data:
                log.warning("No valid blocklist data found.")
                return

            all_profile_ids = await get_all_profiles(api_sem, auth_client)
            pids = [pid for pid in all_profile_ids if pid not in EXCLUDED_IDS]
            
            await asyncio.gather(*(
                sync_single_profile(profile_sem, api_sem, auth_client, pid, valid_remote_data, state) 
                for pid in pids
            ))
    
    finally:
        save_state(state)

if __name__ == "__main__":
    asyncio.run(main_async())
