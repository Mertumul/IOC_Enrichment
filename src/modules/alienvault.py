import httpx
from dynaconf import Dynaconf
from scan.type_detector import detect_ioc_type
import logging

logging.basicConfig(level=logging.INFO)
settings = Dynaconf(settings_file="settings.toml")
API_KEY = settings.api_keys.alienvault
IP_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
DOMAIN_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain/"
HASH_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/file/"
URL_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/url/"


async def fetch_alien_vault_data(indicator: str) -> dict:
    """
    Fetches AlienVault data for the given indicator (IP address, domain, file hash, or URL).

    Args:
        indicator (str): The indicator to be checked.

    Returns:
        dict: JSON data obtained from the AlienVault API.
    """
    indicator_type = await detect_ioc_type(indicator)

    match indicator_type:
        case "ip":
            base_url = IP_BASE_URL
        case "domain":
            base_url = DOMAIN_BASE_URL
        case "file_hash":
            base_url = HASH_BASE_URL
        case "url":
            base_url = URL_BASE_URL
        case _:
            logging.error("Geçersiz indicator türü: %s", indicator_type)
            return None

    url = base_url + indicator + "/general"
    headers = {"X-OTX-API-KEY": API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logging.error("API isteği basarisiz oldu: %s", e)
            return None
