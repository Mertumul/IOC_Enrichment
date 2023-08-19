from datetime import datetime

from sqlalchemy.dialects.postgresql import insert

from database.session import DOMAIN, HASH, IP, URL, Base, SessionLocal, logging


async def insert_ip_ioc(ioc_data: IP) -> None:
    ioc_data.created_at = datetime.utcnow()  # Şu anki tarih ve zamanı ayarlayalım
    with SessionLocal() as db:
        try:
            stmt = (
                insert(IP)
                .values(
                    ioc=ioc_data.ioc,
                    ioc_type=ioc_data.ioc_type,
                    blacklist=ioc_data.blacklist,
                    malicious=ioc_data.malicious,
                    is_vpn = ioc_data.is_vpn,
                    can_remote_access = ioc_data.can_remote_access,
                    current_opened_port = ioc_data.current_opened_port,
                    remote_port = ioc_data.remote_port,
                    ids = ioc_data.ids,
                    scanning_record = ioc_data.scanning_record,
                    ip_category = ioc_data.ip_category,
                    related_tags=ioc_data.related_tags,
                    geometric_location=ioc_data.geometric_location,
                    country=ioc_data.country,
                    isp=ioc_data.isp,
                    created_at=ioc_data.created_at,  # Tarih ve zamanı da ekleyelim
                    abuseipdb=ioc_data.abuseipdb,
                    greynoise=ioc_data.greynoise,
                    whois=ioc_data.whois,
                )
                .on_conflict_do_nothing(index_elements=["ioc"])
            )
            db.execute(stmt)
            db.commit()
        finally:
            logging.info("save process completed")


async def insert_domain_ioc(ioc_data: DOMAIN) -> None:
    ioc_data.created_at = datetime.utcnow()  # Şu anki tarih ve zamanı ayarlayalım
    with SessionLocal() as db:
        try:
            stmt = (
                insert(DOMAIN)
                .values(
                    ioc=ioc_data.ioc,
                    ioc_type=ioc_data.ioc_type,
                    ip=ioc_data.ip,
                    dns_record=ioc_data.dns_record,
                    blacklist=ioc_data.blacklist,
                    malicious=ioc_data.malicious,
                    related_tags=ioc_data.related_tags,
                    geometric_location=ioc_data.geometric_location,
                    country=ioc_data.country,
                    isp=ioc_data.isp,
                    created_at=ioc_data.created_at,  # Tarih ve zamanı da ekleyelim
                    whois=ioc_data.whois,
                )
                .on_conflict_do_nothing(index_elements=["ioc"])
            )
            db.execute(stmt)
            db.commit()
        finally:
            logging.info("save process completed")


async def insert_hash_ioc(ioc_data: HASH) -> None:
    ioc_data.created_at = datetime.utcnow()  # Şu anki tarih ve zamanı ayarlayalım
    with SessionLocal() as db:
        try:
            stmt = (
                insert(HASH)
                .values(
                    ioc=ioc_data.ioc,
                    ioc_type=ioc_data.ioc_type,
                    malicious=ioc_data.malicious,
                    related_tags=ioc_data.related_tags,
                    created_at=ioc_data.created_at,  # Tarih ve zamanı da ekleyelim
                    hash_algorithm=ioc_data.hash_algorithm,
                    file_name=ioc_data.file_name,
                    file_size=ioc_data.file_size,
                    file_type=ioc_data.file_type,
                    threat_label=ioc_data.threat_label,
                    magic=ioc_data.magic,
                    tr_ID=ioc_data.tr_ID,
                    tlsh=ioc_data.tlsh,
                    vhash=ioc_data.vhash,
                    pulse_info=ioc_data.pulse_info,
                )
                .on_conflict_do_nothing(index_elements=["ioc"])
            )
            db.execute(stmt)
            db.commit()
        finally:
            logging.info("save process completed")


async def insert_url_ioc(ioc_data: URL) -> None:
    ioc_data.created_at = datetime.utcnow()  # Şu anki tarih ve zamanı ayarlayalım
    with SessionLocal() as db:
        try:
            stmt = (
                insert(URL)
                .values(
                    ioc=ioc_data.ioc,
                    ioc_type=ioc_data.ioc_type,
                    suspicious=ioc_data.suspicious,
                    unsafe=ioc_data.unsafe,  # Tarih ve zamanı da ekleyelim
                    risk_score=ioc_data.risk_score,
                    malware=ioc_data.malware,
                    spamming=ioc_data.spamming,
                    phishing=ioc_data.phishing,
                    adult=ioc_data.adult,
                    ip_address=ioc_data.ip_address,
                    country=ioc_data.country,
                    servers=ioc_data.servers,
                    contacted_urls=ioc_data.contacted_urls,
                    related_tags=ioc_data.related_tags,
                    pulse_info=ioc_data.pulse_info,
                    whois=ioc_data.whois,
                )
                .on_conflict_do_nothing(index_elements=["ioc"])
            )
            db.execute(stmt)
            db.commit()
        finally:
            logging.info("save process completed")


# psql2 asenkron
async def get_ioc_from_db(ioc_value: str, ioc_type: str):
    with SessionLocal() as db:
        match ioc_type:
            case "ip":
                ioc = db.query(IP).filter(IP.ioc == ioc_value).first()
            case "domain":
                ioc = db.query(DOMAIN).filter(DOMAIN.ioc == ioc_value).first()
            case "file_hash":
                ioc = db.query(HASH).filter(HASH.ioc == ioc_value).first()
            case "url":
                ioc = db.query(URL).filter(URL.ioc == ioc_value).first()
            case _:
                logging.error("Unknown data type!!!")
                return None
        
        return ioc


async def delete_ioc(ioc_value: str, ioc_type: str) -> None:
    with SessionLocal() as db:
        ioc = None
        match ioc_type:
            case "ip":
                ioc = db.query(IP).filter(IP.ioc == ioc_value).first()
            case "domain":
                ioc = db.query(DOMAIN).filter(DOMAIN.ioc == ioc_value).first()
            case "file_hash":
                ioc = db.query(HASH).filter(HASH.ioc == ioc_value).first()
            case "url":
                ioc = db.query(URL).filter(URL.ioc == ioc_value).first()
            case _:
                logging.error("Unknown data type!!!")

        if ioc:
            db.delete(ioc)
            db.commit()