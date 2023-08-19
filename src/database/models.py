from datetime import datetime

from sqlalchemy import (Boolean, Column, DateTime, Integer, String,
                        UniqueConstraint)
from sqlalchemy.orm import declarative_base
Base = declarative_base()


class IP(Base):
    __tablename__ = "IP"
    __table_args__ = (UniqueConstraint("ioc", name="unique_ip"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc = Column(String)
    ioc_type = Column(String)
    malicious = Column(Boolean)
    is_vpn = Column(Boolean)
    can_remote_access = Column(Boolean)
    current_opened_port = Column(String)
    remote_port = Column(String)
    ids = Column(String)
    scanning_record = Column(String)
    ip_category = Column(String)
    related_tags = Column(String)
    blacklist = Column(Boolean)
    country = Column(String)
    geometric_location = Column(String)
    isp = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    abuseipdb = Column(String)
    greynoise = Column(String)
    whois = Column(String)


class DOMAIN(Base):
    __tablename__ = "domain"
    __table_args__ = (UniqueConstraint("ioc", name="unique_domain"),)
    id = Column(Integer, primary_key=True, autoincrement=True)

    ioc = Column(String)
    ioc_type = Column(String)
    ip = Column(String)
    dns_record = Column(String)
    malicious = Column(Boolean)
    related_tags = Column(String)
    blacklist = Column(Boolean)
    country = Column(String)
    geometric_location = Column(String)
    isp = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    whois = Column(String)


class HASH(Base):
    __tablename__ = "file_hash"
    __table_args__ = (UniqueConstraint("ioc", name="unique_filehash"),)
    id = Column(Integer, primary_key=True, autoincrement=True)

    ioc = Column(String)
    ioc_type = Column(String)
    malicious = Column(Boolean)
    related_tags = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    hash_algorithm = Column(String)  # Hash algoritması
    file_name = Column(String)  # Dosya adı
    file_size = Column(Integer)  # Dosya boyutu
    file_type = Column(String)  # Dosya türü
    threat_label = Column(String)  # Yaratıcı uygulama
    magic = Column(String)
    tr_ID = Column(String)
    tlsh = Column(String)
    vhash = Column(String)
    pulse_info = Column(String)


class URL(Base):
    __tablename__ = "url"
    __table_args__ = (UniqueConstraint("ioc", name="unique_url"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc = Column(String)
    ioc_type = Column(String)
    suspicious = Column(Boolean)
    unsafe = Column(Boolean)
    risk_score = Column(Integer)
    malware = Column(Boolean)
    spamming = Column(Boolean)
    phishing = Column(Boolean)
    adult = Column(Boolean)
    ip_address = Column(String)
    country = Column(String)
    servers = Column(String)
    contacted_urls = Column(String)
    related_tags = Column(String)
    pulse_info = Column(String)
    whois = Column(String)
