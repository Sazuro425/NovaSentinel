#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pathlib import Path
from typing import Dict, Any
import time, json

from client.backend.log.mylog import get_custom_logger
logger = get_custom_logger("api.receiver")

app = FastAPI(title="NovaSentinel Receiver API", version="1.0.0")
REPORTS_DIR = Path("reports"); REPORTS_DIR.mkdir(exist_ok=True)

@app.post("/ingest")
async def ingest(report: Dict[str, Any]):
    """Réception d’un rapport JSON produit ailleurs (scanner)."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    outfile = REPORTS_DIR / f"scan_{ts}.json"
    outfile.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    logger.info("Report saved: %s", outfile)          # ← corrigé
    return {"status": "saved", "file": str(outfile)}

@app.get("/latest")
async def latest():
    """Renvoie le dernier rapport JSON enregistré."""
    files = sorted(REPORTS_DIR.glob("scan_*.json"), reverse=True)
    if not files:
        raise HTTPException(404, "No report yet")
    return json.loads(files[0].read_text())
