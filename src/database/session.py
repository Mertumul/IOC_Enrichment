import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, IP, DOMAIN, HASH, URL
from dynaconf import Dynaconf

logging.basicConfig(level=logging.INFO)

settings = Dynaconf(settings_file="settings.toml")
# PostgreSQL database connection URL
DATABASE_URL = f"postgresql://{settings.database.user}:{settings.database.password}@{settings.database.host}:5432/{settings.database.database}"
engine = create_engine(DATABASE_URL)

Base.metadata.create_all(engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
