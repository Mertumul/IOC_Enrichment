import json
from modules.virustotal import fetch_virustotal_data
from modules.whois import fetch_whois_data
from modules.ip_api import fetch_ip_api_data
from modules.blacklistchecker import run_blacklist_check
from modules.alienvault import fetch_alien_vault_data
from modules.dnslookup import fetch_dns_lookup_data
from database.models import DOMAIN

import logging

logging.basicConfig(level=logging.INFO)


# malicious_or_not
async def parse_virustotal_data(data: dict) -> bool:
    """
    Parses VirusTotal data to determine if the IP is marked as malicious.

    Args:
        data (dict): JSON data obtained from the VirusTotal API.

    Returns:
        bool: True if the IP is malicious, False otherwise.
    """

    # Checking if the IP is marked as malicious
    last_analysis_stats = data["attributes"].get("last_analysis_stats", {})
    is_malicious = last_analysis_stats.get("malicious", 0) > 0

    return True if is_malicious else False


# country-city,geolocation,
async def parse_geolocation_data(data: json) -> tuple:
    """
    Parses geolocation data to extract IP information.

    Args:
        data (dict): JSON data obtained from the ip-api.com API.

    Returns:
        tuple: (IP address, country, city, latitude, longitude, ISP).
    """
        
    try:
        ip = data.get("query", None)
        country = data.get("country", None)
        city = data.get("city", None)
        lat = data.get("lat", None)
        lon = data.get("lon", None)
        isp = data.get("isp", None)
        return ip, country, city, lat, lon, isp
    except json.JSONDecodeError:
        logging.error("Invalid JSON data")
        return None, None, None, None, None


async def parse_alien_vault_data(data: dict) -> str:
    """
    Parses AlienVault data to extract related tags.

    Args:
        data (dict): JSON data obtained from the AlienVault API.

    Returns:
        str: Comma-separated list of related tags.
    """
        
    tags = set()
    pulse_info = data.get("pulse_info", {})
    if "pulses" in pulse_info:
        for pulse in pulse_info["pulses"]:
            pulse_tags = pulse.get("tags", [])
            tags.update(tag.lower() for tag in pulse_tags)
    tags_str = ", ".join(tags)
    return tags_str


async def create_domain_ioc(domain: str) -> DOMAIN:
    """
    Creates a Domain IOC object by fetching and parsing various data sources.

    Args:
        domain (str): The domain name to be analyzed.

    Returns:
        DOMAIN: An instance of the DOMAIN model with parsed IOC data.
    """

    virustotal_json_data = await fetch_virustotal_data(domain)
    is_malicious = await parse_virustotal_data(virustotal_json_data["data"])
    blacklist_result = await run_blacklist_check(domain)
    whois_data = await fetch_whois_data(domain)
    alienvault_data = await fetch_alien_vault_data(domain)
    related_tags = await parse_alien_vault_data(alienvault_data)
    geolocation_data = await fetch_ip_api_data(domain)
    ip, country, city, lat, lon, isp = await parse_geolocation_data(geolocation_data)
    country = country if country is not None else ""
    city = city if city is not None else ""
    country_city = country + "-" + city
    geolocation = str(lat) + "," + str(lon)
    dns_record = await fetch_dns_lookup_data(domain)
    dns_record_data = json.dumps(dns_record)

    domain_ioc = DOMAIN(
        ioc=domain,
        ioc_type="Domain",
        ip=ip,
        dns_record=dns_record_data,
        malicious=is_malicious,
        related_tags=related_tags,
        blacklist=blacklist_result,
        country=country_city,
        geometric_location=geolocation,
        isp=isp,
        whois=whois_data,
    )

    return domain_ioc
