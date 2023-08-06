import httpx
from dynaconf import Dynaconf
settings = Dynaconf(settings_file="settings.toml")
key = settings.api_keys.greynoise

async def fetch_greynoise_data(ip: str) -> str:
    """
    Fetches Greynoise data for the given IP address using the Greynoise API.

    Args:
        ip (str): The IP address to be checked.

    Returns:
        str: Textual response obtained from the Greynoise API.
    """
    
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "accept": "application/json",
        "key": key
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        return response.text
