from uuid import uuid4
import asyncio
from typing import Dict, List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel

# import direct depuis ton backend existant
from backend.scan.launch_scan import main as launch_scan
from backend.utils.myjson import save_scan, load_scan

app = FastAPI()
scans: Dict[str, dict | None] = {}      # id → résultat (None = en cours)

class ScanRequest(BaseModel):
    hosts: List[str]

@app.get("/")
def read_root():
    return {"API": "Network Scan API"}

@app.post("/scan", response_model=str)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Lance un scan en tâche de fond et renvoie un ID pour récupérer le résultat.
    """
    scan_id = str(uuid4())
    scans[scan_id] = None
    # on peut passer hosts à la fonction launch_scan si adaptée
    background_tasks.add_task(run_launch_scan, scan_id)
    return scan_id

async def run_launch_scan(scan_id: str):
    try:
        # Appel synchrone dans un thread pour ne pas bloquer
        result = await asyncio.to_thread(launch_scan)
        # save and store result
        save_scan(scan_id, result)
        scans[scan_id] = result
    except Exception as e:
        scans[scan_id] = {"error": str(e)}

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """
    Récupère le résultat du scan si terminé, sinon lève 202.
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    result = scans[scan_id]
    if result is None:
        raise HTTPException(status_code=202, detail="Scan in progress")
    return result
