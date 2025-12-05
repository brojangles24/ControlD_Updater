#!/usr/bin/env python3
"""
Control D Sync (Genius Edition)
-------------------------------
The ultimate state-machine for Control D.
1. Fetches Remote & Local state in parallel.
2. Calculates exact 'Delta' (Additions/Deletions).
3. Uses Heuristics to choose strategy:
   - Zero Drift -> Sleep (0s)
   - Small Drift -> Surgical Patch (2-5s)
   - Massive Drift -> Nuclear Rebuild (60s+)
"""

import os
import logging
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple

import httpx
from dotenv import load_dotenv

# --------------------------------------------------------------------------- #
# 0. Config & Tuning
# --------------------------------------------------------------------------- #
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("genius-sync")

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")
PROFILE_IDS = [p.strip() for p in os.getenv("PROFILE", "").split(",") if p.strip()]

FOLDER_URLS = [
    # --- Aggressive Security ---
    # Renamed from 'badware-hoster' to 'hoster'
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/hoster-folder.json",
    
    # Renamed from 'spam-tlds' to 'tlds'
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/tlds-folder.json",
    
    # Renamed from 'spam-idns' to 'idns' (International Domain Names / Fake Text)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/idns-folder.json",
    
    # --- Native Trackers (Renamed: Dots instead of dashes) ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native.amazon-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native.apple-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native.microsoft-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native.tiktok-folder.json",
]

BATCH_SIZE = 1000
MAX_RETRIES = 3
# The "Tipping Point": If we have to delete more than this many rules, 
# it's faster to nuke the whole folder than to delete them one by one.
SURGICAL_THRESHOLD = 200 
CONCURRENCY_LIMIT = 10

# --------------------------------------------------------------------------- #
# 1. Network Core
# --------------------------------------------------------------------------- #

async def _api(client: httpx.AsyncClient, method: str, endpoint: str, **kwargs) -> httpx.Response:
    url = f"{API_BASE}{endpoint}"
    for i in range(MAX_RETRIES):
        try:
            resp = await client.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp
        except (httpx.HTTPError, httpx.TimeoutException):
            if i == MAX_RETRIES - 1: raise
            await asyncio.sleep(0.5 * (2 ** i))
    return None

async def fetch_json(client: httpx.AsyncClient, url: str) -> Optional[Dict]:
    try:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        log.error(f"Failed to download {url}: {e}")
        return None

# --------------------------------------------------------------------------- #
# 2. State & Analysis
# --------------------------------------------------------------------------- #

async def get_profile_tree(client: httpx.AsyncClient, profile_id: str) -> Dict[str, Any]:
    """
    Returns: { "FolderName": { "id": "grp_123", "rules": {"example.com": "rule_abc123"} } }
    We map Hostname -> RuleID so we can surgically delete specific rules later.
    """
    groups_resp = await _api(client, "GET", f"/profiles/{profile_id}/groups")
    groups = groups_resp.json().get("body", {}).get("groups", [])
    
    folder_map = {}
    
    async def fetch_folder_details(grp):
        name = grp["group"].strip()
        pk = grp["PK"]
        
        # Get rules
        rules_resp = await _api(client, "GET", f"/profiles/{profile_id}/rules/{pk}")
        rules_data = rules_resp.json().get("body", {}).get("rules", [])
        
        # Map Hostname -> PK (Crucial for Delta Sync)
        rule_dict = {r["PK"]: r["key"] for r in rules_data if r.get("PK") and r.get("key")}
        return name, {"id": pk, "rules": rule_dict}

    tasks = [fetch_folder_details(g) for g in groups]
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, tuple):
                folder_map[res[0]] = res[1]
                
    return folder_map

# --------------------------------------------------------------------------- #
# 3. Operations (Surgical vs Nuclear)
# --------------------------------------------------------------------------- #

async def op_nuclear_rebuild(client, pid, name, meta, hostnames, old_id):
    """The 'Sledgehammer': Delete folder, create new, push all."""
    log.info(f"☢️  [{name}] NUCLEAR REBUILD (Faster for massive changes)")
    if old_id:
        await _api(client, "DELETE", f"/profiles/{pid}/groups/{old_id}")
    
    # Create
    cr = await _api(client, "POST", f"/profiles/{pid}/groups", 
                    json={"name": name, "do": meta["do"], "status": meta["status"]})
    
    # Verify ID (Handling API race conditions)
    new_id = cr.json().get("body", {}).get("groups", [{}])[0].get("PK")
    if not new_id:
        await asyncio.sleep(1)
        grps = await _api(client, "GET", f"/profiles/{pid}/groups")
        for g in grps.json().get("body", {}).get("groups", []):
            if g["group"] == name: new_id = g["PK"]
    
    if not new_id: return

    # Batch Push
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    tasks = []
    for batch in batches:
        data = {"do": str(meta["do"]), "status": str(meta["status"]), "group": str(new_id)}
        for j, h in enumerate(batch): data[f"hostnames[{j}]"] = h
        
        # Async push batches (We don't need to wait for order)
        tasks.append(_api(client, "POST", f"/profiles/{pid}/rules", data=data))
    
    await asyncio.gather(*tasks)

async def op_surgical_patch(client, pid, name, folder_id, meta, to_add, to_delete, rule_map):
    """The 'Scalpel': Add specific domains, Delete specific IDs."""
    log.info(f"🩺 [{name}] SURGICAL PATCH (+{len(to_add)} / -{len(to_delete)})")
    
    # 1. Deletions (Must happen individually or in small parallel bursts)
    if to_delete:
        async def delete_one(hostname):
            rule_id = rule_map.get(hostname)
            if rule_id:
                await _api(client, "DELETE", f"/profiles/{pid}/rules/{rule_id}")

        # Limit concurrency for deletions so we don't 429
        sem = asyncio.Semaphore(10)
        async def safe_delete(h):
            async with sem: await delete_one(h)
            
        await asyncio.gather(*[safe_delete(h) for h in to_delete])

    # 2. Additions (Can be batched)
    if to_add:
        batches = [list(to_add)[i:i + BATCH_SIZE] for i in range(0, len(to_add), BATCH_SIZE)]
        tasks = []
        for batch in batches:
            data = {"do": str(meta["do"]), "status": str(meta["status"]), "group": str(folder_id)}
            for j, h in enumerate(batch): data[f"hostnames[{j}]"] = h
            tasks.append(_api(client, "POST", f"/profiles/{pid}/rules", data=data))
        await asyncio.gather(*tasks)

# --------------------------------------------------------------------------- #
# 4. The Brain
# --------------------------------------------------------------------------- #

async def sync_profile(client: httpx.AsyncClient, profile_id: str, remote_data: List[Dict]):
    log.info(f"--- Analyzing Profile: {profile_id} ---")
    
    # Fetch current state (Map of Hostnames -> RuleIDs)
    current_state = await get_profile_tree(client, profile_id)
    
    tasks = []
    
    for remote in remote_data:
        name = remote["group"]["group"].strip()
        do = remote["group"]["action"]["do"]
        status = remote["group"]["action"]["status"]
        
        remote_hosts = set([r["PK"] for r in remote.get("rules", []) if r.get("PK")])
        
        # Default: Nuclear if folder missing
        strategy = "nuclear"
        curr_hosts = set()
        folder_id = None
        rule_map = {}
        
        if name in current_state:
            folder_data = current_state[name]
            folder_id = folder_data["id"]
            rule_map = folder_data["rules"] # dict {hostname: rule_pk}
            curr_hosts = set(rule_map.keys())
            
            # --- The Genius Calculation ---
            if remote_hosts == curr_hosts:
                log.info(f"✅ [{name}] Perfectly synced. Skipping.")
                continue
                
            to_add = remote_hosts - curr_hosts
            to_delete = curr_hosts - remote_hosts
            
            # Cost Analysis
            # If we have to delete too many individual rules, the API gets slow.
            # Nuclear is O(1) delete + O(N) write. Surgical is O(N) delete + O(N) write.
            if len(to_delete) > SURGICAL_THRESHOLD:
                strategy = "nuclear"
            else:
                strategy = "surgical"
        else:
            to_add = remote_hosts
            to_delete = set()

        # Enqueue the work
        if strategy == "nuclear":
            tasks.append(op_nuclear_rebuild(client, profile_id, name, {"do": do, "status": status}, list(remote_hosts), folder_id))
        else:
            tasks.append(op_surgical_patch(client, profile_id, name, folder_id, {"do": do, "status": status}, to_add, to_delete, rule_map))

    if tasks:
        await asyncio.gather(*tasks)
    else:
        log.info(f"🎉 Profile {profile_id} required no changes.")

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN in .env")
        return

    async with httpx.AsyncClient(timeout=60, headers={"Authorization": f"Bearer {TOKEN}"}) as client:
        # 1. Fetch Remote Lists (Once)
        log.info("Fetching remote lists...")
        raw = await asyncio.gather(*[fetch_json(client, url) for url in FOLDER_URLS])
        valid_remotes = [r for r in raw if r]

        # 2. Discover Profiles
        targets = PROFILE_IDS
        if not targets:
            log.info("Auto-discovering profiles...")
            resp = await _api(client, "GET", "/profiles")
            targets = [p["PK"] for p in resp.json().get("body", {}).get("profiles", [])]

        # 3. Execute
        for pid in targets:
            await sync_profile(client, pid, valid_remotes)

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
