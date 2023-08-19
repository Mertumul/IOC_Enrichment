import logging

import httpx
from dynaconf import Dynaconf

logging.basicConfig(level=logging.INFO)
settings = Dynaconf(settings_file="settings.toml")

api_key = settings.api_keys.apininjas


async def fetch_dns_lookup_data(domain: str) -> dict:
    """
    Fetches DNS lookup data for the given domain using the api-ninjas API.

    Args:
        domain (str): The domain to be looked up.

    Returns:
        dict: JSON data obtained from the api-ninjas API.
    """
    api_url = f"https://api.api-ninjas.com/v1/dnslookup?domain={domain}"
    headers = {"X-Api-Key": api_key}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(api_url, headers=headers)
            response.raise_for_status()
            return response.json()  # <-- Burada response.json() kullanın
        except httpx.HTTPError as e:
            logging.error("Error: %s", e)
            return None
