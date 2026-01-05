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
    """Ensures the Nuclear Blocks folder exists for GUI visibility."""
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

async def block_punycode(client: httpx.AsyncClient, profile_id: str):
    """Injects permanent Punycode blocks."""
    folder_id = await get_or_create_folder(client, profile_id)
    
    # We block both the root punycode and subdomains
    # Setting ttl to 0 makes the rule permanent
    targets = ["xn--*", "*.xn--*"]
    
    for i, target in enumerate(targets):
        data = {
            f"hostnames[{i}]": target,
            "do": 0,
            "status": 1,
            "group": folder_id,
            "ttl": 0  # 0 = Permanent / No Expiration
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
            log.info(f"🚀 Found {len(pids)} profiles. Starting permanent lockdown...")

            tasks = [block_punycode(client, pid) for pid in pids]
            await asyncio.gather(*tasks)
            
        except Exception as e:
            log.error(f"❌ Failed to fetch profiles: {e}")

if __name__ == "__main__":
    asyncio.run(main())
