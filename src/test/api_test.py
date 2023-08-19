import sys
sys.path.append("..")
import pytest
from fastapi.testclient import TestClient
from api.api import app

client = TestClient(app)


#--------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_search_form():
    response = client.get("/")
    assert response.status_code == 200
#--------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_search_endpoint_ip():
    response = client.get("/search/?q=8.8.8.8")
    assert response.status_code == 200
#--------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_search_endpoint_domain():
    response = client.get("/search/?q=example.com")
    assert response.status_code == 200
#--------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_search_endpoint_hash():
    response = client.get("/search/?q=177add288b289d43236d2dba33e65956")
    assert response.status_code == 200
#--------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_search_endpoint_url():
    response = client.get("/search/?q=https://example.com")
    assert response.status_code == 200
#--------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_search_endpoint_invalid_query():
    invalid_query = "invalid_query"
    response = client.get(f"/search/?q={invalid_query}")
    assert response.status_code == 404
#--------------------------------------------------------------------------------------------------------------------------------