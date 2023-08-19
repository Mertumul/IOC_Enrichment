import sys
sys.path.append("..")
import pytest
from scan.ip_scan import parse_virustotal_data, parse_geolocation_data, parse_alien_vault_data, parse_criminalip_data
from scan.domain_scan import parse_geolocation_data_domain
from scan.hash_scan import parse_virustotal_data_hash
from scan.url_scan import parse_ipquality_data, parse_urlscanio_data, list_to_string

#--------------------------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("data, expected_result", [
    # ... diğer test durumları ...
    ({"attributes": {}}, False),  # Test with empty "attributes"
    ({"attributes": {"last_analysis_stats": {"malicious": 0}}}, False),  # Test with non-malicious IP
    ({"attributes": {"last_analysis_stats": {"malicious": 1}}}, True),   # Test with malicious IP
    ({"attributes": {"last_analysis_stats": {"malicious": 2}}}, True),
    ({"attributes": {"last_analysis_stats": {"malicious": 10}}}, True),
    ({"attributes": {}}, False),  # Test with missing "last_analysis_stats"
    ({}, False),  # Test with missing "attributes"
])
@pytest.mark.asyncio
async def test_parse_virustotal_data(data, expected_result):
    result = await parse_virustotal_data(data)
    assert result == expected_result
    
#--------------------------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_parse_geolocation_data():
    # Test with regular data
    test_data = {
        "query": "112.186.224.34",
        "status": "success",
        "continent": "Asia",
        "continentCode": "AS",
        "country": "South Korea",
        "countryCode": "KR",
        "region": "43",
        "regionName": "North Chungcheong",
        "city": "North Chungcheong",
        "district": "",
        "zip": "279",
        "lat": 36.8197,
        "lon": 127.6565,
        "timezone": "Asia/Seoul",
        "offset": 32400,
        "currency": "KRW",
        "isp": "Korea Telecom",
        "org": "Kornet",
        "as": "AS4766 Korea Telecom",
        "asname": "KIXS-AS-KR",
        "mobile": False,
        "proxy": False,
        "hosting": False
    }
    
    result = await parse_geolocation_data(test_data)
    expected_result = (
        "South Korea", "North Chungcheong", 36.8197, 127.6565, "Korea Telecom"
    )
    assert result == expected_result

    # Edge case: Test with missing data
    test_data_missing = {}
    expected_missing_result = (
        None, None, None, None, None
    )
    missing_result = await parse_geolocation_data(test_data_missing)
    assert missing_result == expected_missing_result

#--------------------------------------------------------------------------------------------------------------------------------------------------
# Test parse_geolocation_data_domain function
@pytest.mark.asyncio
async def test_parse_geolocation_data_domain():
    # Test with regular data
    test_data = {
        "query": "112.186.224.34",
        "status": "success",
        "continent": "Asia",
        "continentCode": "AS",
        "country": "South Korea",
        "countryCode": "KR",
        "region": "43",
        "regionName": "North Chungcheong",
        "city": "North Chungcheong",
        "district": "",
        "zip": "279",
        "lat": 36.8197,
        "lon": 127.6565,
        "timezone": "Asia/Seoul",
        "offset": 32400,
        "currency": "KRW",
        "isp": "Korea Telecom",
        "org": "Kornet",
        "as": "AS4766 Korea Telecom",
        "asname": "KIXS-AS-KR",
        "mobile": False,
        "proxy": False,
        "hosting": False
    }
    
    result = await parse_geolocation_data_domain(test_data)
    expected_result = (
        "112.186.224.34", "South Korea", "North Chungcheong", 36.8197, 127.6565, "Korea Telecom"
    )
    assert result == expected_result

    test_data_missing = {}
    expected_missing_result = (
        None, None, None, None, None, None
    )
    missing_result = await parse_geolocation_data_domain(test_data_missing)
    assert missing_result == expected_missing_result
    


#--------------------------------------------------------------------------------------------------------------------------------------------------
#testing parse_alien_vault_data
@pytest.fixture
async def sample_data():
    return {
        "pulse_info": {
            "pulses": [
                {"tags": ["Tag1", "Tag2"]},
                {"tags": ["Tag3", "Tag4"]},
            ]
        }
    }

@pytest.mark.asyncio
async def test_parse_alien_vault_data_parses_tags(sample_data):
    result = await parse_alien_vault_data(await sample_data)
    expected_tags = {"tag1", "tag2", "tag3", "tag4"}
    assert set(result.split(", ")) == expected_tags

@pytest.mark.asyncio
async def test_parse_alien_vault_data_with_empty_data():
    result = await parse_alien_vault_data(None)
    assert result is None

@pytest.mark.asyncio
async def test_parse_alien_vault_data_with_missing_pulse_info():
    data = {
        "random_key": "random_value"
    }
    result = await parse_alien_vault_data(data)
    assert result is None

@pytest.mark.asyncio
async def test_parse_alien_vault_data_with_empty_pulse_list():
    data = {
        "pulse_info": {
            "pulses": []
        }
    }
    result = await parse_alien_vault_data(data)
    assert result == ""

@pytest.mark.asyncio
async def test_parse_alien_vault_data_with_no_tags():
    data = {
        "pulse_info": {
            "pulses": [
                {"tags": []},
                {"tags": []},
            ]
        }
    }
    result = await parse_alien_vault_data(data)
    assert result == ""


#--------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_parse_virustotal_data_hash():
    # Test with regular data
    test_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1
                },
                "type_description": "Executable",
                "tlsh": "abc123",
                "vhash": "def456",
                "popular_threat_classification": {
                    "suggested_threat_label": "Malware"
                },
                "size": 1024,
                "magic": "PE",
                "trid": "Windows Executable",
                "names": ["malware.exe"]
            }
        }
    }
    expected_result = (
        True, "Executable", "abc123", "def456", "Malware", 1024, "PE", "Windows Executable", ["malware.exe"]
    )
    result = await parse_virustotal_data_hash(test_data)
    assert result == expected_result

    # Test with missing attributes
    test_data_missing_attributes = {"data": {}}
    expected_missing_attributes_result = (
        False, None, None, None, None, 0, None, None, []
    )
    missing_attributes_result = await parse_virustotal_data_hash(test_data_missing_attributes)
    assert missing_attributes_result == expected_missing_attributes_result


#--------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_parse_ipquality_data():
    # Test with regular data
    test_data = {
        "suspicious": False,
        "unsafe": False,
        "risk_score": 0,
        "malware": False,
        "spamming": False,
        "phishing": False,
        "adult": False
    }
    expected_result = (
        False, False, 0, False, False, False, False
    )
    result = await parse_ipquality_data(test_data)
    assert result == expected_result

    # Test with missing keys
    test_data_missing_keys = {}
    expected_missing_keys_result = (None, None, None, None, None, None, None)
    missing_keys_result = await parse_ipquality_data(test_data_missing_keys)
    assert missing_keys_result == expected_missing_keys_result
#--------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_parse_urlscanio_data():
    # Test with regular data
    test_data = {
        "lists": {
            "ips": ["192.168.1.1", "8.8.8.8"],
            "countries": ["US", "CA"],
            "servers": ["nginx", "apache"],
            "urls": ["https://example.com", "http://test.com"]
        }
    }
    expected_result = (
        ["192.168.1.1", "8.8.8.8"],
        ["US", "CA"],
        ["nginx", "apache"],
        ["https://example.com", "http://test.com"]
    )
    result = await parse_urlscanio_data(test_data)
    assert result == expected_result

    # Test with missing keys
    test_data_missing_keys = {}
    expected_missing_keys_result = ([], [], [], [])
    missing_keys_result = await parse_urlscanio_data(test_data_missing_keys)
    assert missing_keys_result == expected_missing_keys_result
#--------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_to_string():
    # Test with a regular list
    test_list = ["item1", "item2", "item3"]
    expected_result = "item1,item2,item3"
    result = await list_to_string(test_list)
    assert result == expected_result

    # Test with an empty list
    empty_list = []
    expected_empty_result = ""
    empty_result = await list_to_string(empty_list)
    assert empty_result == expected_empty_result

    # Test with None
    none_result = await list_to_string(None)
    assert none_result == expected_empty_result
    #--------------------------------------------------------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_parse_criminalip_data():
    data = """
    {
        "is_vpn": true,
        "can_remote_access": false,
        "current_opened_port": {"data": []},
        "remote_port": {"data": []},
        "ids": {"data": []},
        "scanning_record": {"data": []},
        "ip_category": {"data": []}
    }
    """
    
    result = await parse_criminalip_data(data)
    
    assert result == (True, False, None, None, None, None, None)

    # Test with non-empty data
    data = """
    {
        "is_vpn": false,
        "can_remote_access": true,
        "current_opened_port": {"data": [{"socket_type": "tcp", "port": 80}]},
        "remote_port": {"data": [{"socket_type": "tcp", "port": 22}]},
        "ids": {"data": [{"classification": "malware", "message": "Malware detected"}]},
        "scanning_record": {"data": [{"count": 1, "classification": "scanning"}]},
        "ip_category": {"data": [{"type": "suspicious"}]}
    }
    """
    
    result = await parse_criminalip_data(data)
    
    assert result == (False, True, "tcp:80", "tcp:22", "malware: Malware detected", "1 scanning", "suspicious")