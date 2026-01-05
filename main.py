#!/usr/bin/env python3
import os
import logging
import asyncio
import httpx

# --- 1. Config ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("punycode-nuclear")

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")

# --- 2. Helper Logic ---

async def get_or_create_folder(client: httpx.AsyncClient, profile_id: str) -> str:
    """Ensures a 'Nuclear Blocks' folder exists so rules are visible in GUI."""
    try:
        resp = await client.get(f"{API_BASE}/profiles/{profile_id}/groups")
        resp.raise_for_status()
        groups = resp.json().get("body", {}).get("groups", [])
        
        for g in groups:
            if g["group"].strip() == "Nuclear Blocks":
                return g["PK"]
        
        log.info(f"📁 [Profile {profile_id}] Creating 'Nuclear Blocks' folder...")
        resp = await client.post(
            f"{API_BASE}/profiles/{profile_id}/groups",
            data={"name": "Nuclear Blocks", "do": 0, "status": 1}
        )
        return resp.json().get("body", {}).get("PK")
    except Exception as e:
        log.error(f"❌ [Profile {profile_id}] Folder creation failed: {e}")
        return None

async def block_punycode_nuclear(client: httpx.AsyncClient, profile_id: str):
    """
    Injects permanent Punycode blocks for root (xn--*) and subdomains (*.xn--*).
    Sets ttl=0 to ensure rules never expire.
    """
    folder_id = await get_or_create_folder(client, profile_id)
    if not folder_id:
        return

    targets = ["xn--*", "*.xn--*"]
    
    for i, target in enumerate(targets):
        data = {
            f"hostnames[{i}]": target,
            "do": 0,      # Block
            "status": 1,  # Active
            "group": folder_id,
            "ttl": 0      # Permanent
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
                    log.info(f"ℹ️  [Profile {profile_id}] {target} already exists.")
                else:
                    log.error(f"❌ [Profile {profile_id}] {target} Rejected: {msg}")
                    
        except Exception as e:
            log.error(f"❌ [Profile {profile_id}] API Error on {target}: {e}")

# --- 3. Main Execution ---

async def main():
    if not TOKEN:
        log.error("Missing TOKEN environment variable.")
        return

    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {TOKEN}"}, 
        timeout=30,
        follow_redirects=True
    ) as client:
        
        log.info("📥 Fetching all profiles...")
        try:
            resp = await client.get(f"{API_BASE}/profiles")
            resp.raise_for_status()
            profiles = resp.json().get("body", {}).get("profiles", [])
            
            pids = [p["PK"] for p in profiles]
            log.info(f"🚀 Found {len(pids)} profiles. Starting lockdown...")

            # Run all blocks concurrently
            tasks = [block_punycode_nuclear(client, pid) for pid in pids]
            await asyncio.gather(*tasks)
            
        except Exception as e:
            log.error(f"❌ Failed to fetch profiles: {e}")

if __name__ == "__main__":
    asyncio.run(main())
