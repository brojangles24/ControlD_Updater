import os
import json
import logging
import asyncio
import hashlib
import tomllib
import datetime
import csv
import io
from typing import Dict, List, Any

import httpx

# --------------------------------------------------------------------------- #
# 0. Load Configuration from TOML
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("control-d-sync")

try:
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
except Exception as e:
    log.error(f"❌ Critical error loading config.toml: {e}")
    exit(1)

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")
STATE_FILE = "state.json"

BATCH_SIZE = config.get("batch_size", 200)
CONCURRENCY_LIMIT = config.get("concurrency_limit", 3) 
RULE_LIMIT = config.get("rule_limit", 10000)
RULES_CONFIG = config.get("rules", [])

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

def calculate_hash(action_buckets: Dict, profile_rule: str) -> str:
    stable_buckets = {f"{k[0]}_{k[1]}": sorted(v) for k, v in action_buckets.items()}
    payload = {"buckets": stable_buckets, "profile_rule": profile_rule}
    serialized = json.dumps(payload, sort_keys=True).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()

# --------------------------------------------------------------------------- #
# 2. Async Clients & Helpers
# --------------------------------------------------------------------------- #

async def _retry_request(sem: asyncio.Semaphore, request_func):
    async with sem:
        for attempt in range(3):
            try:
                response = await request_func()
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                if e.response.status_code in [400, 401]:
                    raise
                if attempt == 2:
                    log.error(f"❌ API Error: {e.response.text}")
                    raise
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt == 2:
                    raise
            await asyncio.sleep(1 * (2 ** attempt))

async def fetch_gh_json(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    resp = await client.get(url)
    resp.raise_for_status()
    return resp.json()

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
        payload = {"do": int(do), "status": int(status), "group": str(folder_id), "hostnames": batch}
        
        max_attempts = 5 if is_first else 3
        for attempt in range(max_attempts):
            try:
                async with api_sem:
                    resp = await client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=payload)
                resp.raise_for_status()
                return 
            except httpx.HTTPStatusError as e:
                if is_first and e.response.status_code == 404:
                    await asyncio.sleep(1)
                    continue
                if e.response.status_code == 400:
                    try:
                        err_msg = e.response.json().get("error", {}).get("message", "").lower()
                        if "limit" in err_msg:
                            log.error(f"❌ Hard API Limit Reached! Cannot push batch to {folder_name}.")
                            raise e 
                    except Exception:
                        pass
                    break
                if attempt == max_attempts - 1:
                    raise e
                await asyncio.sleep(1)

        log.debug(f"⚠️ [{folder_name}] Batch rejected. Filtering invalid entries individually...")
        fallback_tasks = []
        for h in batch:
            single_payload = {**payload, "hostnames": [h]}
            async def send_single(p):
                async with api_sem:
                    try:
                        await client.post(f"{API_BASE}/profiles/{profile_id}/rules", json=p)
                    except Exception:
                        pass 
            fallback_tasks.append(send_single(single_payload))
        await asyncio.gather(*fallback_tasks)

    if not batches:
        return
    
    await send_batch(batches[0], is_first=True)
    if len(batches) > 1:
        tasks = [send_batch(b, is_first=False) for b in batches[1:]]
        await asyncio.gather(*tasks)

# --------------------------------------------------------------------------- #
# 3. Core Sync Logic
# --------------------------------------------------------------------------- #

async def sync_rule_to_profile(api_sem: asyncio.Semaphore, auth_client: httpx.AsyncClient, profile_id: str, profile_pseudonym: str, rule_payload: Dict, state: Dict):
    name = rule_payload["name"]
    new_hash = rule_payload["hash"]
    rule_count = rule_payload["rule_count"]
    action_buckets = rule_payload["action_buckets"]

    log.info(f"🔄 Processing [{name}] for profile: {profile_pseudonym}")
    
    current_rules = await get_rule_count(api_sem, auth_client, profile_id)
    current_folders = await list_folders(api_sem, auth_client, profile_id)
    
    if profile_pseudonym not in state:
        state[profile_pseudonym] = {}

    if name in current_folders and state[profile_pseudonym].get(name) == new_hash:
        log.info(f"⏩ [{name}] -> ({profile_pseudonym}) No changes. Skipping.")
        return
    
    if current_rules + rule_count > RULE_LIMIT:
        log.error(f"❌ [{name}] -> ({profile_pseudonym}) Sync aborted. Exceeds 10k limit.")
        return

    temp_name = f"{name}_tmp"

    if temp_name in current_folders:
        log.warning(f"🧹 Removing stranded '{temp_name}' from a previous failed run...")
        try:
            await _retry_request(api_sem, lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{current_folders[temp_name]}"))
        except Exception:
            pass

    log.info(f"⚡ [{name}] -> ({profile_pseudonym}) executing zero-downtime swap...")
    try:
        await _retry_request(api_sem, lambda: auth_client.post(
            f"{API_BASE}/profiles/{profile_id}/groups", json={"name": temp_name}
        ))
        
        updated_folders = await list_folders(api_sem, auth_client, profile_id)
        new_id = updated_folders.get(temp_name)
        
        if new_id:
            push_tasks = [
                push_rules(api_sem, auth_client, profile_id, temp_name, new_id, b_do, b_status, hostnames)
                for (b_do, b_status), hostnames in action_buckets.items()
            ]
            await asyncio.gather(*push_tasks)
            
            if name in current_folders:
                await _retry_request(api_sem, lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{current_folders[name]}"))

            await _retry_request(api_sem, lambda: auth_client.put(
                f"{API_BASE}/profiles/{profile_id}/groups/{new_id}", json={"name": name}
            ))

            state[profile_pseudonym][name] = new_hash
            log.info(f"✅ [{name}] -> ({profile_pseudonym}) Sync complete.")
        else:
            log.error(f"❌ [{name}] -> ({profile_pseudonym}) Failed to verify temp folder creation.")

    except Exception as e:
        log.error(f"❌ [{name}] -> ({profile_pseudonym}) Sync failed: {e}")
    finally:
        try:
            cleanup_folders = await list_folders(api_sem, auth_client, profile_id)
            if temp_name in cleanup_folders:
                log.info(f"🧹 Cleaning up orphaned temp folder on {profile_pseudonym}")
                await _retry_request(api_sem, lambda: auth_client.delete(f"{API_BASE}/profiles/{profile_id}/groups/{cleanup_folders[temp_name]}"))
        except Exception:
            pass

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var. Execution stopped.")
        return

    state = load_state()

    env_profiles = {
        "guest": os.getenv("GUEST"),
        "iot": os.getenv("IOT"),
        "main": os.getenv("MAIN"),
        "user_i": os.getenv("USER_I"),
        "user_k": os.getenv("USER_K"),
    }
    active_profiles = {k: v for k, v in env_profiles.items() if v}

    if not RULES_CONFIG:
        log.info("⏩ No rules configured. Skipping sync.")
        return

    try:
        async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60, http2=True) as auth_client, \
                   httpx.AsyncClient(timeout=60, http2=True) as gh_client:
            
            api_sem = asyncio.Semaphore(5) 
            fetched_rules = []
            nsfw_blocks = set()

            # --- FETCH BACKGROUND RAW TEXT NSFW LIST FOR FILTERING ONLY ---
            nsfw_url = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt"
            log.info(f"📥 Fetching background NSFW text list for cross-referencing...")
            try:
                resp = await gh_client.get(nsfw_url)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    # Ignore comments and empty lines
                    if line and not line.startswith(('#', '!', '/')):
                        nsfw_blocks.add(line.lower())
                log.info(f"✅ Loaded {len(nsfw_blocks):,} domains from NSFW background list.")
            except Exception as e:
                log.error(f"❌ Failed to fetch background NSFW list: {e}")
            # --------------------------------------------------------------

            # ---------------------------------------------------------------- #
            # PASS 1: Async Fetch Baseline for ControlD Configured Rules
            # ---------------------------------------------------------------- #
            for r_item in RULES_CONFIG:
                raw_url_input = r_item.get("rule_url")
                rule_name = r_item.get("rule", "Unnamed Rule")
                profile_rule = r_item.get("profile_rule", "none").strip().lower()

                if not raw_url_input:
                    continue

                urls = [raw_url_input] if isinstance(raw_url_input, str) else raw_url_input
                combined_raw_rules = []
                fallback_folder_name = "Unnamed Folder"
                fetch_failed = False

                for url in urls:
                    log.info(f"📥 Fetching blocklist source for: {rule_name} -> {url}")
                    try:
                        parsed_json = await fetch_gh_json(gh_client, url)
                        combined_raw_rules.extend(parsed_json.get("rules", []))
                        
                        if "group" in parsed_json and "group" in parsed_json["group"]:
                            fallback_folder_name = parsed_json["group"]["group"]
                    except Exception as e:
                        log.error(f"❌ Failed to fetch dataset from source URL {url}: {e}")
                        fetch_failed = True
                        break 

                if fetch_failed or not combined_raw_rules:
                    continue

                fetched_rules.append({
                    "r_item": r_item,
                    "profile_rule": profile_rule,
                    "combined_raw_rules": combined_raw_rules,
                    "fallback_folder_name": fallback_folder_name
                })

            # ---------------------------------------------------------------- #
            # PASS 2: Structural Verification and Dynamic Cross-Checking
            # ---------------------------------------------------------------- #
            rule_payloads = []
            for item in fetched_rules:
                r_item = item["r_item"]
                profile_rule = item["profile_rule"]
                combined_raw_rules = item["combined_raw_rules"]
                fallback_folder_name = item["fallback_folder_name"]

                folder_display_name = r_item.get("rule", fallback_folder_name).strip()
                action_buckets = {}
                final_rules_count = 0

                for rule in combined_raw_rules:
                    hostname = rule.get("PK")
                    if not hostname:
                        continue
                    
                    normalized_host = hostname.strip().lower()
                    
                    r_action = rule.get("action", {})
                    do = int(r_action.get("do", 0))
                    status = int(r_action.get("status", 1))

                    # If this is an ALLOW rule (do == 1), check it against the raw text NSFW blocklist
                    if do == 1 and normalized_host in nsfw_blocks:
                        log.warning(f"⚠️ [{folder_display_name}] Dropping allowed domain '{hostname}' because it matches the NSFW blocklist.")
                        continue

                    key = (do, status)
                    action_buckets.setdefault(key, []).append(hostname)
                    final_rules_count += 1

                if not action_buckets:
                    log.info(f"⏩ [{folder_display_name}] Empty dataset after processing. Skipping payload.")
                    continue

                payload = {
                    "config_item": r_item,
                    "name": folder_display_name,
                    "hash": calculate_hash(action_buckets, profile_rule),
                    "rule_count": final_rules_count,
                    "action_buckets": action_buckets
                }
                rule_payloads.append(payload)

            for payload in rule_payloads:
                r_item = payload["config_item"]
                excluded = [p.strip().lower() for p in r_item.get("excluded_profiles", [])]
                folder_display_name = payload["name"]

                for pseud, pid in active_profiles.items():
                    if pseud in excluded:
                        log.info(f"⏩ Rule [{folder_display_name}] explicitly excludes profile: {pseud}. Skipping target.")
                        continue
                    
                    await sync_rule_to_profile(api_sem, auth_client, pid, pseud, payload, state)

            # --------------------------------------------------------------------------- #
            # CSV ANALYTICS EXPORT (1-Hour Rolling Window)
            # --------------------------------------------------------------------------- #
            ANALYTICS_CLUSTER = config.get("analytics_cluster")
            stats_cache = {pseud: {"total": 0, "blocked": 0} for pseud in active_profiles.keys()}

            if ANALYTICS_CLUSTER:
                log.info("📊 Fetching last hour of analytics via CSV export...")
                try:
                    now = datetime.datetime.now(datetime.timezone.utc)
                    one_hour_ago = now - datetime.timedelta(hours=1)
                    
                    start_str = one_hour_ago.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                    end_str = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                    
                    cluster_host = ANALYTICS_CLUSTER.replace("https://", "").rstrip("/")
                    csv_url = f"https://{cluster_host}/v2/activity-log/csv?startTime={start_str}&endTime={end_str}"
                    
                    resp = await _retry_request(api_sem, lambda: auth_client.get(csv_url))
                    
                    reader = csv.DictReader(io.StringIO(resp.text))
                    pid_to_pseud = {v: k for k, v in active_profiles.items()}
                    
                    for row in reader:
                        pid = row.get("profileId")
                        if pid in pid_to_pseud:
                            pseud = pid_to_pseud[pid]
                            stats_cache[pseud]["total"] += 1
                            
                            action = str(row.get("action", "")).strip().lower()
                            if action in ["0", "block", "blocked"]:
                                stats_cache[pseud]["blocked"] += 1

                except Exception as e:
                    log.error(f"❌ Failed to parse analytics CSV: {e}")
            else:
                log.info("⏩ No 'analytics_cluster' defined in config.toml. Skipping stats fetch.")

    finally:
        save_state(state)

if __name__ == "__main__":
    asyncio.run(main_async())
