import logging
import xml.etree.ElementTree as ET

import httpx
from dynaconf import Dynaconf

logging.basicConfig(level=logging.INFO)
settings = Dynaconf(settings_file="settings.toml")

api_key = settings.api_keys.whoisxmlapi


async def fetch_whois_data(domain_name: str) -> str:
    """
    Fetches WHOIS data for the given domain name using the whoisxmlapi.

    Args:
        domain_name (str): The domain name to be looked up.

    Returns:
        str: Textual WHOIS data obtained from the whoisxmlapi.
    """

    base_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    url = f"{base_url}?apiKey={api_key}&domainName={domain_name}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            xml_str = response.text
            root = ET.fromstring(xml_str)
            values = []
            for element in root.iter():
                if element.text and not element.text.strip().startswith("#"):
                    values.append(element.text.strip())
            return " ".join(values)
        except httpx.RequestError as e:
            logging.error("API istegi basarisisz oldu: %s", e)
            return None
