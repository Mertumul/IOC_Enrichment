import sys
sys.path.append("..")
import pytest
from modules.abuseipdb import fetch_abuseipdb_data
from modules.alienvault import fetch_alien_vault_data
from modules.blacklistchecker import run_blacklist_check
from modules.dnslookup import fetch_dns_lookup_data
from modules.greynoise import fetch_greynoise_data
from modules.ip_api import fetch_ip_api_data
from modules.ipqualityscore import fetch_ipqualityscore_data
from modules.urlscan_io import fetch_urlscanio_data
from modules.virustotal import fetch_virustotal_data
from modules.whois import fetch_whois_data
from modules.criminalip import fetch_criminalip_data

URL_INDICATOR = "https://kompoz2.com/tv/264152/lust-cinema-a-feminist-man.html"
IP_INDICATOR = "137.184.35.63"
DOMAIN_INDICATOR = "lookintomyeyes.site"
HASH_INDICATOR = "177add288b289d43236d2dba33e65956"


@pytest.mark.asyncio
async def test_fetch_abuseipdb_data():
    result = await fetch_abuseipdb_data(IP_INDICATOR)
    assert result is not None

@pytest.mark.asyncio
@pytest.mark.parametrize("indicator", [IP_INDICATOR, DOMAIN_INDICATOR, HASH_INDICATOR, URL_INDICATOR])
async def test_fetch_alien_vault_and_virustotal_data(indicator):
    result = await fetch_alien_vault_data(indicator)
    assert result is not None

@pytest.mark.asyncio
async def test_run_blacklist_check():
    result = await run_blacklist_check(IP_INDICATOR)
    assert result is not None
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_fetch_dns_lookup_data():
    result = await fetch_dns_lookup_data(DOMAIN_INDICATOR)
    assert result is not None


@pytest.mark.asyncio
async def test_fetch_greynoise_data():
    result = await fetch_greynoise_data(IP_INDICATOR)
    assert result is not None


@pytest.mark.asyncio
async def test_fetch_ip_api_data():
    result = await fetch_ip_api_data(IP_INDICATOR)
    assert result is not None


@pytest.mark.asyncio
async def test_fetch_ipqualityscore_data():
    result = await fetch_ipqualityscore_data(URL_INDICATOR)
    assert result is not None

@pytest.mark.asyncio
async def test_fetch_urlscanio_data():
    result = await fetch_urlscanio_data(URL_INDICATOR)
    assert result is not None

@pytest.mark.asyncio
@pytest.mark.parametrize("indicator", [IP_INDICATOR, DOMAIN_INDICATOR, HASH_INDICATOR])
async def test_fetch_virustotal_data(indicator):
    result = await fetch_virustotal_data(indicator)
    assert result is not None

@pytest.mark.asyncio
async def test_fetch_whois_data():
    result = await fetch_whois_data(IP_INDICATOR)

    assert result is not None

@pytest.mark.asyncio
async def test_fetch_ipcriminal_data():
    result = await fetch_criminalip_data(IP_INDICATOR)

    assert result is not None