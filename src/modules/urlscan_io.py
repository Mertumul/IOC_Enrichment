import httpx
import asyncio
import logging
from dynaconf import Dynaconf

settings = Dynaconf(settings_file="settings.toml")
api_key = settings.api_keys.urlscan_io


async def fetch_urlscanio_data(url_to_scan: str):
    """
    Fetches urlscan.io data for the given URL using the urlscan.io API.

    Args:
        url_to_scan (str): The URL to be scanned.

    Returns:
        ip_list (list): List of IP addresses obtained from urlscan.io.
        country (list): List of countries obtained from urlscan.io.
        servers (list): List of servers obtained from urlscan.io.
        urls (list): List of URLs obtained from urlscan.io.
    """

    async with httpx.AsyncClient() as client:
        headers = {
            "Content-Type": "application/json",
            "API-Key": api_key,
        }

        data = {
            "url": url_to_scan,
            "public": "on",
        }

        # Scanning the URL
        response = await client.post(
            "https://urlscan.io/api/v1/scan/", json=data, headers=headers
        )
        if response.status_code != 200:
            print("Tarama basarisiz oldu!")
            return None, None, None, None

        scan_data = response.json()
        uuid = scan_data["uuid"]
        logging.info("Tarama tamamlandi. UUID: %s", uuid)
        # Wait for the result
        await asyncio.sleep(40)

        # Getting the result
        result_url = f"https://urlscan.io/api/v1/result/{uuid}"
        result_response = await client.get(result_url)
        if result_response.status_code != 200:
            logging.error("Sonuç alinamadi!")
            return None, None, None, None

        result_data = result_response.json()
        ip_list = result_data.get("lists", {}).get("ips", [])
        country = result_data.get("lists", {}).get("countries", [])
        servers = result_data.get("lists", {}).get("servers", [])
        urls = result_data.get("lists", {}).get("urls", [])

        return ip_list, country, servers, urls
