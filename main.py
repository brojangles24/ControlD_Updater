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

# --------------------------------------------------------------------------- #
# 1. Nuclear Logic
# --------------------------------------------------------------------------- #

async def get_or_create_nuclear_folder(client: httpx.AsyncClient, profile_id: str) -> str:
    """Ensures a 'Nuclear Blocks' folder exists so rules are visible in GUI."""
    try:
        resp = await client.get(f"{API_BASE}/profiles/{profile_id}/groups")
        groups = resp.json().get("body", {}).get("groups", [])
        for g in groups:
            if g["group"].strip() == "Nuclear Blocks":
                return g["PK"]
        
        # Create it if missing
        log.info(f"📁 [Profile {profile_id}] Creating 'Nuclear Blocks' folder...")
        resp = await client.post(
            f"{API_BASE}/profiles/{profile_id}/groups",
            data={"name": "Nuclear Blocks", "do": 0, "status": 1}
        )
        return resp.json().get("body", {}).get("PK")
    except Exception:
        return None

async def ensure_nuclear_rules(client: httpx.AsyncClient, profile_id: str):
    """Injects Punycode and TLD wildcards into the specific profile."""
    folder_id = await get_or_create_nuclear_folder(client, profile_id)
    
    # List of wildcards for total lockdown
    targets = ["xn--*", "*.zip", "*.mov", "*.top", "*.su", "*.sbs", "*.cfd", "*.icu"]
    
    for target in targets:
        data = {
            "hostname": target,
            "do": 0,
            "status": 1,
            "group": folder_id, # Linking to folder ensures visibility
            "ttl": 300
        }
        
        try:
            resp = await client.post(
                f"{API_BASE}/profiles/{profile_id}/rules",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if resp.status_code == 200:
                log.info(f"✅ [Profile {profile_id}] Blocked: {target}")
            else:
                body = resp.json()
                msg = body.get("error", {}).get("message", "Unknown Error")
                if "already exists" in msg.lower():
                    pass # Silently skip existing
                else:
                    log.error(f"❌ [Profile {profile_id}] {target} Rejected: {msg}")
                    
        except Exception as e:
            log.error(f"❌ [Profile {profile_id}] API Error on {target}: {e}")

# --------------------------------------------------------------------------- #
# 2. Main Execution
# --------------------------------------------------------------------------- #

async def main_async():
    if not TOKEN:
        log.error("Missing TOKEN env var.")
        return

    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=60) as auth_client:
        log.info("📥 Fetching all profiles...")
        resp = await auth_client.get(f"{API_BASE}/profiles")
        profiles = resp.json().get("body", {}).get("profiles", [])
        
        pids = [p["PK"] for p in profiles]
        log.info(f"🚀 Found {len(pids)} profiles. Starting Nuclear Sync...")

        # Run all profiles concurrently
        tasks = [ensure_nuclear_rules(auth_client, pid) for pid in pids]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main_async())
