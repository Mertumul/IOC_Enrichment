import httpx
from scan.type_detector import detect_ioc_type
import logging
from dynaconf import Dynaconf
settings = Dynaconf(settings_file="settings.toml")
logging.basicConfig(level=logging.INFO)
apikey = settings.api_keys.virustotal


async def fetch_virustotal_data(indicator:str) -> dict:
    """
    Fetches VirusTotal data for the given indicator (file hash, IP address, or domain) using the VirusTotal API.

    Args:
        indicator (str): The indicator to be checked.

    Returns:
        dict: JSON data obtained from the VirusTotal API.
    """
        
    match indicator_type := await detect_ioc_type(indicator):
        case "file_hash":
            url = f"https://www.virustotal.com/api/v3/files/{indicator}"
        case "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        case "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
        case _:
            logging.error("Geçersiz indicator türü: %s", indicator_type)
            return None

    headers = {"accept": "application/json", "x-apikey": apikey}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data
    except httpx.RequestError as e:
        logging.error("API cagrisi sirasinda bir hata oluştu: %s", e)
        return None
