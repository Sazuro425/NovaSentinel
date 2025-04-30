#!/usr/bin/env python3
import os
from sqlalchemy import create_engine, text, MetaData
from sqlalchemy.ext.declarative import declarative_base
from mylog import database_log


DB_HOST = os.getenv("DBHost")
DB_USER = os.getenv("DBUser")
DB_PASS = os.getenv("DBPassword")
DB_NAME = "inventory"

URL_ROOT = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/?charset=utf8mb4"
URL_INV  = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4"

engine_root = create_engine(URL_ROOT, echo=False)
if engine_root is None :
    print("erreur")
with engine_root.connect() as conn:
    conn.execute(text(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4"))
engine_root.dispose()

engine = create_engine(URL_INV, echo=True)
Base = declarative_base(metadata=MetaData())
