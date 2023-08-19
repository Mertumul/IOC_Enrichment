import json

import httpx
from dynaconf import Dynaconf

settings = Dynaconf(settings_file="settings.toml")


async def fetch_abuseipdb_data(ip: str):
    """
    Asynchronously fetches AbuseIPDB data for the given IP address.

    Args:
        ip (str): The IP address to be checked.

    Returns:
        json: JSON data obtained from AbuseIPDB.
    """

    api_url = "https://api.abuseipdb.com/api/v2/check"

    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    headers = {"Accept": "application/json", "Key": settings.api_keys.abuseipdb}

    async with httpx.AsyncClient() as client:
        response = await client.get(api_url, params=params, headers=headers)
        response_data = response.json()

        return json.dumps(response_data, sort_keys=True, indent=4)
