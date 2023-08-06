import httpx
import logging

logging.basicConfig(level=logging.INFO)


# ip-info and geolocation data
async def fetch_ip_api_data(query: str) -> dict:
    """
    Fetches ip-info and geolocation data for the given query using the ip-api.com API.

    Args:
        query (str): The query (IP address) to be looked up.

    Returns:
        dict: JSON data obtained from the ip-api.com API.
    """
        
    base_url = "http://ip-api.com/json/"
    url = base_url + query

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            return data
        except httpx.RequestError as e:
            logging.error("API isteği basarisiz oldu: %s", e)
            return None
