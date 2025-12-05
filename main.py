#!/usr/bin/env python3
"""
Control D Sync (Auto-Discovery Edition)
---------------------------------------
1. Auto-discovers ALL profiles if no specific ID is provided.
2. Deletes old folders (Nuclear option).
3. Re-creates folders and pushes rules in batches.
"""

import os
import logging
import time
from typing import Dict, List, Optional, Any, Set

import httpx
# We wrap dotenv in try/except so it runs in GitHub Actions (where .env might not exist)
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

# List of Hagezi Blocklists to Sync
FOLDER_URLS = [
    # --- Aggressive Security ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/badware-hoster-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-tlds-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/spam-idns-folder.json",
    
    # --- Native Trackers (Dots instead of dashes) ---
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-amazon-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-apple-folder.json",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native-tracker-microsoft-folder.json",
    #"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/native.tiktok-folder.json",
    
    # --- Allow Lists ---
    #"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/whitelist-referral-folder.json",
    #"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/controld/whitelist-good-folder.json",
]

BATCH_SIZE = 200 # Safe limit to avoid 400 Errors
MAX_RETRIES = 3
RETRY_DELAY = 1

# --------------------------------------------------------------------------- #
# 1. Clients & Helpers
# --------------------------------------------------------------------------- #
_api = httpx.Client(
    headers={"Accept": "application/json", "Authorization": f"Bearer {TOKEN}"},
    timeout=30,
)
_gh = httpx.Client(timeout=30)
_cache: Dict[str, Dict] = {}

def _retry_request(request_func):
    for attempt in range(MAX_RETRIES):
        try:
            response = request_func()
            response.raise_for_status()
            return response
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            if attempt == MAX_RETRIES - 1:
                if hasattr(e, 'response') and e.response is not None:
                    log.error(f"❌ API Error: {e.response.text}")
                raise
            time.sleep(RETRY_DELAY * (2 ** attempt))

def _api_get(endpoint: str) -> httpx.Response:
    return _retry_request(lambda: _api.get(f"{API_BASE}{endpoint}"))

def _api_delete(endpoint: str) -> httpx.Response:
    return _retry_request(lambda: _api.delete(f"{API_BASE}{endpoint}"))

def _api_post(endpoint: str, data: Dict) -> httpx.Response:
    return _retry_request(lambda: _api.post(f"{API_BASE}{endpoint}", data=data))

def _api_post_form(endpoint: str, data: Dict) -> httpx.Response:
    return _retry_request(lambda: _api.post(f"{API_BASE}{endpoint}", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}))

def fetch_gh_json(url: str) -> Dict[str, Any]:
    if url not in _cache:
        r = _gh.get(url)
        r.raise_for_status()
        _cache[url] = r.json()
    return _cache[url]

# --------------------------------------------------------------------------- #
# 2. Logic
# --------------------------------------------------------------------------- #

def get_all_profiles() -> List[str]:
    """Auto-discover all profiles on the account."""
    try:
        data = _api_get("/profiles").json()
        profiles = [p["PK"] for p in data.get("body", {}).get("profiles", [])]
        log.info(f"🔎 Auto-discovered {len(profiles)} profiles.")
        return profiles
    except Exception as e:
        log.error(f"Failed to auto-discover profiles: {e}")
        return []

def list_folders(profile_id: str) -> Dict[str, str]:
    try:
        data = _api_get(f"/profiles/{profile_id}/groups").json()
        return {g["group"].strip(): g["PK"] for g in data.get("body", {}).get("groups", [])}
    except Exception:
        return {}

def push_rules(profile_id, folder_name, folder_id, do, status, hostnames):
    # Retrieve existing rules to prevent duplicates (400 Bad Request)
    # Note: In a pure nuclear rebuild of a fresh folder, this is empty, 
    # but we keep it for safety if partial syncs occur.
    existing_rules = set() 
    
    # Simple batching
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    total = len(batches)
    
    for i, batch in enumerate(batches, 1):
        # Filter duplicates (if any exist in the destination)
        to_push = [h for h in batch if h not in existing_rules]
        if not to_push: continue

        data = {"do": str(do), "status": str(status), "group": str(folder_id)}
        for j, h in enumerate(to_push):
            data[f"hostnames[{j}]"] = h
            
        try:
            _api_post_form(f"/profiles/{profile_id}/rules", data)
            log.info(f"   └─ Batch {i}/{total}: Pushed {len(to_push)} rules.")
            existing_rules.update(to_push)
        except Exception as e:
            log.error(f"   ❌ Batch {i} failed: {e}")

def sync_profile(profile_id: str):
    log.info(f"--- Syncing Profile: {profile_id} ---")
    
    # 1. Fetch Remote Data
    targets = []
    for url in FOLDER_URLS:
        try:
            targets.append(fetch_gh_json(url))
        except Exception as e:
            log.error(f"Skipping list {url}: {e}")

    # 2. Get Current Folders
    current_folders = list_folders(profile_id)

    # 3. Process Each List
    for remote in targets:
        name = remote["group"]["group"].strip()
        do_action = remote["group"]["action"]["do"]
        status = remote["group"]["action"]["status"]
        rules = [r["PK"] for r in remote.get("rules", []) if r.get("PK")]

        # Nuclear: Delete if exists
        if name in current_folders:
            log.info(f"🗑️  Deleting old '{name}'...")
            try:
                _api_delete(f"/profiles/{profile_id}/groups/{current_folders[name]}")
            except Exception as e:
                log.error(f"Failed to delete {name}: {e}")

        # Create New
        log.info(f"✨ Creating '{name}'...")
        try:
            cr = _api_post(f"/profiles/{profile_id}/groups", data={"name": name, "do": do_action, "status": status})
            # The API returns the whole group list, we have to find our new ID
            # But simpler is to just fetch the list again or parse the response if it contains the ID.
            # Control D POST /groups response usually contains the created object or list.
            # Let's re-fetch to be 100% safe and getting the right PK.
            time.sleep(1) # Consistency delay
            new_folders = list_folders(profile_id)
            new_id = new_folders.get(name)
            
            if new_id:
                push_rules(profile_id, name, new_id, do_action, status, rules)
            else:
                log.error(f"Could not find new folder ID for {name}")

        except Exception as e:
            log.error(f"Failed to create/sync {name}: {e}")

# --------------------------------------------------------------------------- #
# 3. Main
# --------------------------------------------------------------------------- #
def main():
    if not TOKEN:
        log.error("Missing TOKEN env var.")
        exit(1)

    # Check for specific profile arg, otherwise auto-discover
    env_profiles = os.getenv("PROFILE", "").strip()
    if env_profiles:
        pids = [p.strip() for p in env_profiles.split(",") if p.strip()]
    else:
        pids = get_all_profiles()

    if not pids:
        log.error("No profiles found to sync.")
        exit(1)

    for pid in pids:
        sync_profile(pid)

if __name__ == "__main__":
    main()
