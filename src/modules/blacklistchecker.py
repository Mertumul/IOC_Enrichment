from typing import Optional

import httpx
from dynaconf import Dynaconf

settings = Dynaconf(settings_file="settings.toml")

API_KEY = settings.api_keys.blacklist_checker

BASE_URL = "https://api.blacklistchecker.com/check/"


async def run_blacklist_check(query: str) -> Optional[bool]:
    """
    Runs a blacklist check for the given query using the Blacklist Checker API.

    Args:
        query (str): The query to be checked.

    Returns:
        Optional[bool]: True if the query is blacklisted, False if not blacklisted, or None on error.
    """

    url = f"{BASE_URL}{query}"
    async with httpx.AsyncClient(auth=(API_KEY, "")) as client:
        response = await client.get(url)

    if response.status_code == 200:
        data = response.json()
        detections = data["detections"]

        return True if detections > 0 else False

    else:
        return None
