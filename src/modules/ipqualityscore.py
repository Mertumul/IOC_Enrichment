import httpx
import urllib.parse
from dynaconf import Dynaconf

settings = Dynaconf(settings_file="settings.toml")
api_key = settings.api_keys.ipqualityscore


async def fetch_ipqualityscore_data(url: str) -> dict:
    """
    Fetches IP quality score data for the given URL using the ipqualityscore API.

    Args:
        url (str): The URL to be checked.

    Returns:
        dict: JSON data obtained from the ipqualityscore API.
    """
        
    url = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{urllib.parse.quote_plus(url)}"
    additional_params = {"strictness": 0}  # Sabit strictness değeri

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=additional_params)
        response.raise_for_status()  # Check if the request was successful
        return response.json()
