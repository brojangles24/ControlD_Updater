#!/usr/bin/env python3
"""
Control D Sync (Genius Edition)
-------------------------------
1. Auto-discovers ALL profiles (skipping excluded ones).
2. Fetches HageZi blocklists from GitHub.
3. Performs "Nuclear Sync": Deletes old folder, creates new one, pushes rules.
4. "Smart Fallback": If a batch fails (due to duplicates), it retries rules 1-by-1.
"""

import os
import logging
import time
from typing import Dict, List, Optional, Any, Set

import httpx
# Handle dotenv for local dev vs GitHub Actions
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

# HageZi Blocklists
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

BATCH_SIZE = 200  # Safe limit for Control D API
MAX_RETRIES = 3
RETRY_DELAY = 1

# --------------------------------------------------------------------------- #
# 1. Clients & Helpers
# --------------------------------------------------------------------------- #

# Auth Client (For Control D)
_api = httpx.Client(
    headers={"Accept": "application/json", "Authorization": f"Bearer {TOKEN}"},
    timeout=30,
)

# Clean Client (For GitHub - No Headers)
_gh = httpx.Client(timeout=30)

_cache: Dict[str, Dict] = {}

def _retry_request(request_func):
    """Retries a request with exponential backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            response = request_func()
            # Special handling: 400 errors are business logic errors (duplicates), 
            # we want to raise them immediately so logic can handle them, 
            # NOT retry the exact same bad request 3 times.
            if response.status_code == 400:
                response.raise_for_status()
            
            response.raise_for_status()
            return response
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            # If it's a 400, stop retrying and let the caller handle it
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 400:
                raise
                
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
    """
    Pushes rules in batches. 
    If a batch fails (usually due to a duplicate rule existing elsewhere), 
    it falls back to pushing that batch 1-by-1 to ensure non-duplicates still get added.
    """
    # Track what we've added in this run to avoid sending duplicates within the same list
    existing_rules = set() 
    
    batches = [hostnames[i:i + BATCH_SIZE] for i in range(0, len(hostnames), BATCH_SIZE)]
    total = len(batches)
    
    for i, batch in enumerate(batches, 1):
        to_push = [h for h in batch if h not in existing_rules]
        if not to_push: continue

        data = {"do": str(do), "status": str(status), "group": str(folder_id)}
        
        # Prepare batch data
        batch_data = data.copy()
        for j, h in enumerate(to_push):
            batch_data[f"hostnames[{j}]"] = h
            
        try:
            # 1. Try pushing the whole batch
            _api_post_form(f"/profiles/{profile_id}/rules", batch_data)
            log.info(f"   └─ Batch {i}/{total}: Pushed {len(to_push)} rules.")
            existing_rules.update(to_push)
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                # 2. BATCH FAILED - Smart Fallback
                log.warning(f"   ⚠️ Batch {i}/{total} hit a conflict (Duplicate). Retrying individually...")
                
                success_count = 0
                for h in to_push:
                    single_data = data.copy()
                    single_data["hostnames[0]"] = h
                    try:
                        _api_post_form(f"/profiles/{profile_id}/rules", single_data)
                        success_count += 1
                        existing_rules.add(h)
                    except Exception:
                        # Ignore duplicates on individual push
                        pass
                
                log.info(f"   └─ Batch {i}/{total} (Recovered): Pushed {success_count}/{len(to_push)} rules.")
            else:
                log.error(f"   ❌ Batch {i} failed with unexpected error: {e}")

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
            _api_post(f"/profiles/{profile_id}/groups", data={"name": name, "do": do_action, "status": status})
            
            # Re-fetch list to get the new ID reliably
            time.sleep(1) 
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

    # --- EXCLUSION LIST ---
    EXCLUDED_PROFILES = ["780037lax6zo"]
    # ----------------------

    # Check for specific profile arg, otherwise auto-discover
    env_profiles = os.getenv("PROFILE", "").strip()
    if env_profiles:
        pids = [p.strip() for p in env_profiles.split(",") if p.strip()]
    else:
        pids = get_all_profiles()

    # Filter Exclusions
    pids = [p for p in pids if p not in EXCLUDED_PROFILES]

    if not pids:
        log.error("No profiles found to sync (or all were excluded).")
        exit(1)

    for pid in pids:
        sync_profile(pid)

if __name__ == "__main__":
    main()
