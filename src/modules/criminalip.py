import httpx
from dynaconf import Dynaconf
import json

settings = Dynaconf(settings_file="settings.toml")
API_KEY = settings.api_keys.criminalip

async def fetch_criminalip_data(ip):
    url = f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={ip}"
    headers = {"x-api-key": API_KEY}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.text
    
