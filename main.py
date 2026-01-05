#!/usr/bin/env python3
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
log = logging.getLogger("control-d-sync")

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")
STATE_FILE = "state.json"

# Removed the specific IDN folder as we are using a global wildcard now
FOLDER_URLS = [
    # "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
]

BATCH_SIZE = 200
MAX_RETRIES = 3
CONCURRENCY_LIMIT = 5 

# --------------------------------------------------------------------------- #
# 1. Nuclear Functions
# --------------------------------------------------------------------------- #

async def ensure_punycode_block(client: httpx.AsyncClient, profile_id: str):
    """Injects a wildcard block for ALL Punycode domains (xn--*)"""
    log.info(f"🛡️  [Profile {profile_id}] Ensuring Nuclear Punycode Block...")
    
    # Action 0 = Block, Status 1 = Active
    data = {
        "hostname": "xn--*",
        "do": 0,
        "status": 1,
        "ttl": 300
    }
    
    try:
        # We use the /rules endpoint for custom rules
        resp = await client.post(
            f"{API_BASE}/profiles/{profile_id}/rules",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if resp.status_code == 200:
            log.info(f"✅ [Profile {profile_id}] Punycode wildcard created.")
        elif resp.status_code == 400:
            log.info(f"ℹ️  [Profile {profile_id}] Punycode wildcard already exists.")
    except Exception as e:
        log.error(f"❌ [Profile {profile_id}] Punycode block failed: {e}")

# --------------------------------------------------------------------------- #
# 2. Logic & Sync
# --------------------------------------------------------------------------- #

async def sync_single_profile(sem: asyncio.Semaphore, auth_client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict], state: Dict):
    async with sem:
        log.info(f"--- Processing Profile: {profile_id} ---")
        
        # 1. Apply the Nuclear Punycode Wildcard
        await ensure_punycode_block(auth_client, profile_id)

        # 2. Regular Folder Sync logic
        current_folders = await list_folders(auth_client, profile_id)
        if profile_id not in state: state[profile_id] = {}

        for remote in remote_data:
            name = remote["group"]["group"].strip()
            new_hash = calculate_hash(remote)
            stored_hash = state[profile_id].get(name)
            
            if name in current_folders and stored_hash == new_hash:
                log.info(f"⏩ [{name}] No changes detected. Skipping.")
                continue
            
            log.info(f"🔄 [{name}] Update detected. Syncing...")
            # ... (Rest of your original nuclear delete/create logic stays here)

# (Keeping your original helper functions: calculate_hash, load_state, etc.)
# --------------------------------------------------------------------------- #

async def list_folders(client: httpx.AsyncClient, profile_id: str) -> Dict[str, str]:
    try:
        resp = await client.get(f"{API_BASE}/profiles/{profile_id}/groups")
        data = resp.json()
        return {g["group"].strip(): g["PK"] for g in data.get("body", {}).get("groups", [])}
    except Exception: return {}

def calculate_hash(data: Dict) -> str:
    serialized = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_state(state):
    with open(STATE_FILE, 'w') as f: json.dump(state, f, indent=2, sort_keys=True)

async def get_all_profiles(client: httpx.AsyncClient) -> List[str]:
    resp = await client.get(f"{API_BASE}/profiles")
    return [p["PK"] for p in resp.json().get("body", {}).get("profiles", [])]

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var.")
        return

    EXCLUDED_PROFILES = [""]
    state = load_state()

    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60) as auth_client, \
               httpx.AsyncClient(timeout=60) as gh_client:
        
        log.info("📥 Fetching blocklists...")
        gh_tasks = [gh_client.get(url) for url in FOLDER_URLS]
        responses = await asyncio.gather(*gh_tasks, return_exceptions=True)
        valid_remote_data = [r.json() for r in responses if isinstance(r, httpx.Response)]

        pids = await get_all_profiles(auth_client)
        pids = [p for p in pids if p not in EXCLUDED_PROFILES]

        sem = asyncio.Semaphore(CONCURRENCY_LIMIT)
        tasks = [sync_single_profile(sem, auth_client, pid, valid_remote_data, state) for pid in pids]
        await asyncio.gather(*tasks)
    
    save_state(state)
    log.info("💾 State saved to state.json")

if __name__ == "__main__":
    asyncio.run(main_async())
