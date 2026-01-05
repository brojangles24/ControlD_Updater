#!/usr/bin/env python3
import os
import logging
import asyncio
import httpx

# --- Config ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("punycode-lockdown")

API_BASE = "https://api.controld.com"
TOKEN = os.getenv("TOKEN")

async def get_or_create_folder(client: httpx.AsyncClient, profile_id: str) -> str:
    """Ensures a folder exists so the rule is visible in the GUI."""
    try:
        resp = await client.get(f"{API_BASE}/profiles/{profile_id}/groups")
        groups = resp.json().get("body", {}).get("groups", [])
        for g in groups:
            if "Nuclear" in g["group"]:
                return g["PK"]
        
        # Create folder if not found
        resp = await client.post(
            f"{API_BASE}/profiles/{profile_id}/groups",
            data={"name": "Nuclear Blocks", "do": 0, "status": 1}
        )
        return resp.json().get("body", {}).get("PK")
    except Exception:
        return None

async def block_punycode(client: httpx.AsyncClient, profile_id: str):
    """Injects the xn--* wildcard block."""
    folder_id = await get_or_create_folder(client, profile_id)
    
    # Action 0 = Block, Status 1 = Active
    data = {
        "hostname": "xn--*",
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
            msg = resp.json().get("error", {}).get("message", "Unknown Error")
            if "already exists" in msg.lower():
                log.info(f"ℹ️  [Profile {profile_id}] Punycode block already exists.")
            else:
                log.error(f"❌ [Profile {profile_id}] Rejected: {msg}")
                
    except Exception as e:
        log.error(f"❌ [Profile {profile_id}] API Error: {e}")

async def main():
    if not TOKEN:
        log.error("Missing TOKEN environment variable.")
        return

    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30) as client:
        # Get all profiles
        resp = await client.get(f"{API_BASE}/profiles")
        profiles = resp.json().get("body", {}).get("profiles", [])
        
        # Run blocks concurrently
        tasks = [block_punycode(client, p["PK"]) for p in profiles]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
