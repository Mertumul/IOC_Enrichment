import json
from modules.virustotal import fetch_virustotal_data
from modules.whois import fetch_whois_data
from modules.ip_api import fetch_ip_api_data
from modules.alienvault import fetch_alien_vault_data
from modules.blacklistchecker import run_blacklist_check
from modules.abuseipdb import fetch_abuseipdb_data
from modules.greynoise import fetch_greynoise_data
from database.models import IP
import logging

logging.basicConfig(level=logging.INFO)


# malicious_or_not
async def parse_virustotal_data(data: dict) -> bool:
    """
    Parses VirusTotal data to determine if an IP address is marked as malicious.

    Args:
        data (dict): JSON data obtained from the VirusTotal API.

    Returns:
        bool: True if the IP is malicious, False otherwise.
    """
        
    # Checking if the IP is marked as malicious
    last_analysis_stats = data["attributes"].get("last_analysis_stats", {})
    is_malicious = last_analysis_stats.get("malicious", 0) > 0

    return True if is_malicious else False


async def parse_geolocation_data(data: dict) -> tuple:
    """
    Parses geolocation data to extract relevant information.

    Args:
        data (dict): JSON data obtained from the ip-api.com API.

    Returns:
        tuple: (country, city, latitude, longitude, ISP).
    """

    try:
        country = data.get("country", None)
        city = data.get("city", None)
        lat = data.get("lat", None)
        lon = data.get("lon", None)
        isp = data.get("isp", None)
        return country, city, lat, lon, isp
    except json.JSONDecodeError:
        logging.error("Invalid JSON data")
        return None, None, None, None


async def parse_alien_vault_data(data: dict) -> str:   
    """
    Parses AlienVault data to extract related tags.

    Args:
        data (dict): JSON data obtained from the AlienVault API.

    Returns:
        str: Comma-separated list of related tags.
    """
        
    if data is None or "pulse_info" not in data:
        return None
    tags = set()
    pulse_info = data.get("pulse_info", {})
    if "pulses" in pulse_info:
        for pulse in pulse_info["pulses"]:
            pulse_tags = pulse.get("tags", [])
            tags.update(tag.lower() for tag in pulse_tags)
    tags_str = ", ".join(tags)
    return tags_str


async def create_ioc(ip: str) -> IP:
    """
    Creates an IP IOC object by fetching and parsing various data sources.

    Args:
        ip (str): The IP address to be analyzed.

    Returns:
        IP: An instance of the IP model with parsed IOC data.
    """
        
    virustotal_json_data = await fetch_virustotal_data(ip)
    is_malicious = await parse_virustotal_data(virustotal_json_data["data"])
    related_tags = await parse_alien_vault_data(await fetch_alien_vault_data(ip))
    blacklist_result = await run_blacklist_check(ip)
    whois_data = await fetch_whois_data(ip)
    geolocation_data = await fetch_ip_api_data(ip)
    abuseipdb_data = await fetch_abuseipdb_data(ip)
    abuseipdb_data_str = str(abuseipdb_data)
    greynoise_data = await fetch_greynoise_data(ip)

    country, city, lat, lon, isp = await parse_geolocation_data(geolocation_data)
    country_city = country + "-" + city
    geolocation = str(lat) + "," + str(lon)

    ip_ioc = IP(
        ioc=ip,
        ioc_type="IP",
        malicious=is_malicious,
        related_tags=related_tags,
        blacklist=blacklist_result,
        country=country_city,
        geometric_location=geolocation,
        isp=isp,
        abuseipdb=abuseipdb_data_str,
        greynoise = greynoise_data,
        whois=whois_data,
    )
    return ip_ioc
