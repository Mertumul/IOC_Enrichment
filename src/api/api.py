import sys

sys.path.append("..")
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from scan.type_detector import detect_ioc_type
from scan.ip_scan import create_ioc
from scan.domain_scan import create_domain_ioc
from scan.hash_scan import create_hash_ioc
from scan.url_scan import create_url_ioc
from database.database import (
    insert_ip_ioc,
    insert_domain_ioc,
    insert_hash_ioc,
    insert_url_ioc,
    get_ip_ioc_from_db,
    get_domain_ioc_from_db,
    get_hash_ioc_from_db,
    get_url_ioc_from_db,
)
import uvicorn

app = FastAPI()
templates = Jinja2Templates(directory="../../templates")
app.mount("/static", StaticFiles(directory="../../static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def read_search_form(request: Request):
    """
    Displays the search form on the home page.

    Args:
        request (Request): FastAPI request object.

    Returns:
        HTMLResponse: Template response for the home page.
    """
    return templates.TemplateResponse(
        "index.html", {"request": request, "status": "Success"}
    )


@app.get("/search/", response_class=HTMLResponse)
async def search_endpoint(request: Request, q: str):
    """
    Handles IOC search requests and displays results based on the detected IOC type.

    Args:
        request (Request): FastAPI request object.
        q (str): The IOC value to search for.

    Returns:
        HTMLResponse: Template response for the search result page.
    """
    detected_type = await detect_ioc_type(q)
    ioc = None

    match detected_type:
        case "ip":
            ioc_in_db = await get_ip_ioc_from_db(q)

            if ioc_in_db:
                ioc = ioc_in_db
            else:
                ioc = await create_ioc(q)
                await insert_ip_ioc(ioc)

            return templates.TemplateResponse(
                "search_ip_result.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )

        case "domain":
            ioc_in_db = await get_domain_ioc_from_db(q)

            if ioc_in_db:
                ioc = ioc_in_db
            else:
                ioc = await create_domain_ioc(q)
                await insert_domain_ioc(ioc)

            return templates.TemplateResponse(
                "search_domain_result.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )

        case "file_hash":
            ioc_in_db = await get_hash_ioc_from_db(q)

            if ioc_in_db:
                ioc = ioc_in_db
            else:
                ioc = await create_hash_ioc(q)
                await insert_hash_ioc(ioc)

            return templates.TemplateResponse(
                "search_hash_result.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )
        case "url":
            ioc_in_db = await get_url_ioc_from_db(q)

            if ioc_in_db:
                ioc = ioc_in_db
            else:
                ioc = await create_url_ioc(q)
                await insert_url_ioc(ioc)

            return templates.TemplateResponse(
                "search_url_result.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
