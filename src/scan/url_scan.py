import json
from modules.whois import fetch_whois_data
from modules.alienvault import fetch_alien_vault_data
from modules.ipqualityscore import fetch_ipqualityscore_data
from modules.urlscan_io import fetch_urlscanio_data
from database.models import URL
import logging

logging.basicConfig(level=logging.INFO)


async def parse_alien_vault_data(data: json) -> tuple:
    """
    Parses AlienVault data to extract related tags and pulse details.

    Args:
        data (json): AlienVault JSON data.

    Returns:
        tuple: A tuple containing the related tags as a string and a list of pulse details.
    """
        
    if data is None or "pulse_info" not in data:
        return None, None
    tags = set()
    pulse_info = data.get("pulse_info", {})
    if "pulses" in pulse_info:
        for pulse in pulse_info["pulses"]:
            pulse_tags = pulse.get("tags", [])
            tags.update(tag.lower() for tag in pulse_tags)
    tags_str = ", ".join(tags)

    # pulse info
    pulse_details = []
    pulses = data.get("pulse_info", {}).get("pulses", [])
    for pulse in pulses:
        pulse_name = pulse.get("name", None)
        pulse_description = pulse.get("description", None)
        pulse_tags = pulse.get("tags", [])
        pulse_details.append(
            {"Name": pulse_name, "Description": pulse_description, "Tags": pulse_tags}
        )

    return tags_str, pulse_details


async def parse_ipquality_data(data: json) -> tuple:
    """
    Parses IPQualityScore data to extract relevant information.

    Args:
        data (json): IPQualityScore JSON data.

    Returns:
        tuple: A tuple containing various attributes extracted from the data. The tuple
               elements are (suspicious, unsafe, risk_score, malware, spamming, phishing, adult).
    """
       
    suspicious = data.get("suspicious", None)
    unsafe = data.get("unsafe", None)
    risk_score = data.get("risk_score", None)
    malware = data.get("malware", None)
    spamming = data.get("spamming", None)
    phishing = data.get("phishing", None)
    adult = data.get("adult", None)

    return suspicious, unsafe, risk_score, malware, spamming, phishing, adult

async def parse_urlscanio_data(data: json) -> tuple:
        
    ip_list = data.get("lists", {}).get("ips", [])
    country = data.get("lists", {}).get("countries", [])
    servers = data.get("lists", {}).get("servers", [])
    urls = data.get("lists", {}).get("urls", [])


    return ip_list, country, servers, urls


async def list_to_string(lst):
    if lst is None:
        return ""
    return ",".join(str(item) for item in lst)


async def create_url_ioc(url: str) -> URL:
    """
    Creates an IOC (Indicator of Compromise) object for a given URL.

    This function fetches data from various sources, including AlienVault, IPQualityScore,
    and URLScan.io, and combines them to create a comprehensive IOC object for the provided URL.

    Args:
        url (str): The URL for which the IOC object should be created.

    Returns:
        URL: An IOC object containing information about the URL, including its risk factors,
        related tags, geolocation, WHOIS data, IP quality assessment, and more.
    """
        
    tags_str, pulse_details = await parse_alien_vault_data(
        await fetch_alien_vault_data(url)
    )
    whois_data = await fetch_whois_data(url)
    ipqualityscore_data = await fetch_ipqualityscore_data(url)
    (
        suspicious,
        unsafe,
        risk_score,
        malware,
        spamming,
        phishing,
        adult,
    ) = await parse_ipquality_data(ipqualityscore_data)
    urlscanio_data = await fetch_urlscanio_data(url)
    ip_list, countries, servers, urls = await parse_urlscanio_data(urlscanio_data)
    pulse_info_str = str(pulse_details)
    ip_list = await list_to_string(ip_list)
    countries = await list_to_string(countries)
    servers = await list_to_string(servers)
    urls = await list_to_string(urls)

    url_ioc = URL(
        ioc=url,
        ioc_type="URL",
        suspicious=suspicious,
        unsafe=unsafe,
        risk_score=risk_score,
        malware=malware,
        spamming=spamming,
        phishing=phishing,
        adult=adult,
        ip_address=ip_list,
        country=countries,
        servers=servers,
        contacted_urls=urls,
        related_tags=tags_str,
        pulse_info=pulse_info_str,
        whois=whois_data,
    )
    return url_ioc
