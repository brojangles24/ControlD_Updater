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
log = logging.getLogger("punycode-lockdown")

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")

# --- 2. Helper Logic ---

async def get_or_create_folder(client: httpx.AsyncClient, profile_id: str) -> str:
    """
    Ensures a folder exists so the rule is visible in the GUI.
    Rules without a 'group' often become invisible in the Control D dashboard.
    """
    try:
        resp = await client.get(f"{API_BASE}/profiles/{profile_id}/groups")
        resp.raise_for_status()
        groups = resp.json().get("body", {}).get("groups", [])
        
        for g in groups:
            if g["group"].strip() == "Nuclear Blocks":
                return g["PK"]
        
        # Create folder if not found
        log.info(f"📁 [Profile {profile_id}] Creating 'Nuclear Blocks' folder...")
        resp = await client.post(
            f"{API_BASE}/profiles/{profile_id}/groups",
            data={"name": "Nuclear Blocks", "do": 0, "status": 1}
        )
        return resp.json().get("body", {}).get("PK")
    except Exception as e:
        log.error(f"❌ [Profile {profile_id}] Folder creation failed: {e}")
        return None

async def block_punycode(client: httpx.AsyncClient, profile_id: str):
    """
    Injects the xn--* wildcard block.
    Uses indexed 'hostnames[0]' to satisfy Control D API requirements.
    """
    folder_id = await get_or_create_folder(client, profile_id)
    
    # Action 0 = Block, Status 1 = Active
    # Using hostnames[0] is mandatory for application/x-www-form-urlencoded
    data = {
        "hostnames[0]": "xn--*",
        "do": 0,
        "status": 1,
        "group": folder_id,
        "ttl": 300
    }
    
    try:
        resp = await client.post(
            f"{API_BASE}/profiles/{profile_id}/rules",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if resp.status_code == 200:
            log.info(f"✅ [Profile {profile_id}] Punycode blocked successfully.")
        else:
            body = resp.json()
            msg = body.get("error", {}).get("message", "Unknown Error")
            if "already exists" in msg.lower():
                log.info(f"ℹ️  [Profile {profile_id}] Punycode block already exists.")
            else:
                log.error(f"❌ [Profile {profile_id}] Rejected: {msg}")
                
    except Exception as e:
        log.error(f"❌ [Profile {profile_id}] API Error: {e}")

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

            # Run all blocks concurrently for efficiency
            tasks = [block_punycode(client, pid) for pid in pids]
            await asyncio.gather(*tasks)
            
        except Exception as e:
            log.error(f"❌ Failed to fetch profiles: {e}")

if __name__ == "__main__":
    asyncio.run(main())
