from uuid import uuid4
import asyncio
from typing import Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# import direct depuis ton backend existant
from client.backend.scan.network import scan_with_nmap
from client.backend.utils.myjson import save_scan, load_scan

import datetime
app = FastAPI()
scans: Dict[str, dict | None] = {}      # id → résultat (None = en cours)

class ScanRequest(BaseModel):
    hosts: List[str]

@app.get("/")
def read_root():
    return {"API": "Network Scan API"}

@app.post("/scan", response_model=str)
async def start_scan(request: ScanRequest):

@app.post("/scan", response_model=str)
def report():
    scan_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "-" + str(uuid4())
