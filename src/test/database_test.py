import sys
sys.path.append("..")
from datetime import datetime
import pytest

from database.database import insert_ip_ioc, get_ioc_from_db, delete_ioc, IP

IOC_DATA = IP(
        ioc="192.168.1.1",
        ioc_type="ip",
        blacklist=False,
        malicious=True,
        is_vpn = False,
        can_remote_access = True,
        current_opened_port = "tcp:443, tcp:22",
        remote_port = "tcp:22",
        ids = "some ipcriminal data",
        scanning_record = "some ipcriminal data",
        ip_category = "some ipcriminal data",
        related_tags=["tag1", "tag2"],
        geometric_location=None,
        country="US",
        isp="Some ISP",
        created_at=datetime.utcnow(),
        abuseipdb="Some abuseipdb info",
        greynoise="Some greynoise info",
        whois="Some whois info",
    )


@pytest.mark.asyncio
async def test_insert_and_get_ip_ioc():


    await insert_ip_ioc(IOC_DATA)

    ioc_in_db = await get_ioc_from_db(IOC_DATA.ioc, IOC_DATA.ioc_type)

    assert ioc_in_db.ioc == IOC_DATA.ioc
    assert ioc_in_db.country == IOC_DATA.country
    assert ioc_in_db.isp == IOC_DATA.isp

    
# Test delete_ip_ioc function
@pytest.mark.asyncio
async def test_delete_ip_ioc():
    await delete_ioc(IOC_DATA.ioc, IOC_DATA.ioc_type)

    # Simulate checking if the data is deleted
    deleted_ioc = await get_ioc_from_db(IOC_DATA.ioc, IOC_DATA.ioc_type)
    assert deleted_ioc is None  # Expecting None since the data should be deleted

