#!/usr/bin/env python3
import os
import json
import logging
import asyncio
import hashlib
from typing import Dict, List, Any
import httpx

# --- 1. Config ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scorched-earth")

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")
STATE_FILE = "state.json"

# Specialized Badware list not found in Ultimate/TIF
FOLDER_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
]

# --- 2. Helper Logic ---

def load_state() -> Dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_state(state: Dict):
    with open(STATE_FILE, 'w') as f: json.dump(state, f, indent=2)

def calculate_hash(data: Dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

async def get_or_create_folder(client: httpx.AsyncClient, profile_id: str, name: str) -> str:
    resp = await client.get(f"{API_BASE}/profiles/{profile_id}/groups")
    groups = resp.json().get("body", {}).get("groups", [])
    for g in groups:
        if g["group"].strip() == name: return g["PK"]
    
    res = await client.post(f"{API_BASE}/profiles/{profile_id}/groups", data={"name": name, "do": 0, "status": 1})
    return res.json().get("body", {}).get("PK")

# --- 3. Nuclear Actions ---

async def ensure_punycode_lockdown(client: httpx.AsyncClient, profile_id: str):
    """Enforce permanent block on all Punycode root and subdomains."""
    folder_id = await get_or_create_folder(client, profile_id, "Nuclear Blocks")
    targets = ["xn--*", "*.xn--*"]
    
    for i, target in enumerate(targets):
        data = {f"hostnames[{i}]": target, "do": 0, "status": 1, "group": folder_id, "ttl": 0}
        await client.post(f"{API_BASE}/profiles/{profile_id}/rules", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})

async def sync_badware(client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict], state: Dict):
    """Sync specialized Badware Hoster lists."""
    for remote in remote_data:
        name = remote["group"]["group"].strip()
        new_hash = calculate_hash(remote)
        
        if state.get(profile_id, {}).get(name) == new_hash:
            log.info(f"⏩ [Profile {profile_id}] [{name}] No changes. Skipping.")
            continue

        log.info(f"🔄 [Profile {profile_id}] [{name}] Updating Badware...")
        
        # 1. Delete old folder if exists to clear rules
        groups = (await client.get(f"{API_BASE}/profiles/{profile_id}/groups")).json().get("body", {}).get("groups", [])
        old_id = next((g["PK"] for g in groups if g["group"].strip() == name), None)
        if old_id: await client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{old_id}")

        # 2. Create New Folder
        new_id = await get_or_create_folder(client, profile_id, name)
        
        # 3. Push Rules in Batches
        rules = [r["PK"] for r in remote.get("rules", [])]
        for i in range(0, len(rules), 200):
            batch = rules[i:i+200]
            payload = {"do": 0, "status": 1, "group": new_id}
            for j, hostname in enumerate(batch): payload[f"hostnames[{j}]"] = hostname
            await client.post(f"{API_BASE}/profiles/{profile_id}/rules", data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
        
        state.setdefault(profile_id, {})[name] = new_hash

# --- 4. Main ---

async def main():
    if not TOKEN: return log.error("Missing TOKEN")
    state = load_state()

    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60) as client:
        log.info("📥 Fetching Badware source...")
        remote_data = [(await client.get(url)).json() for url in FOLDER_URLS]
        profiles = (await client.get(f"{API_BASE}/profiles")).json().get("body", {}).get("profiles", [])
        
        for p in profiles:
            pid = p["PK"]
            await ensure_punycode_lockdown(client, pid)
            await sync_badware(client, pid, remote_data, state)
            
    save_state(state)
    log.info("💾 State saved.")

if __name__ == "__main__":
    asyncio.run(main())
