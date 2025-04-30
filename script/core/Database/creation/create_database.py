#!/usr/bin/env python3
import os
from sqlalchemy import create_engine, text, MetaData
from sqlalchemy.ext.declarative import declarative_base
from script.core.log.mylog import get_custom_logger
from script.core.mydotenv import *

logger = get_custom_logger("database")
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_NAME = os.getenv("DB_NAME")

URL_ROOT = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/?charset=utf8mb4"
URL_INV  = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4"

engine_root = create_engine(URL_ROOT, echo=False)

if engine_root is None :
    logger.critical("erreur")
with engine_root.connect() as conn:
    conn.execute(text(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4"))
engine_root.dispose()

engine = create_engine(URL_INV, echo=True)
Base = declarative_base(metadata=MetaData())
