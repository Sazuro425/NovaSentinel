from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from models import Scan, Service, CVE, get_db  # tes modèles SQLAlchemy

app = FastAPI()

class CVESchema(BaseModel):
    id: str
    score: float | str
    link: str

class ServiceSchema(BaseModel):
    port: str
    service: str
    product: str | None
    version: str | None
    info: str | None
    cves: list[CVESchema]

class HostSchema(BaseModel):
    ip: str
    services: list[ServiceSchema]

@app.get("/api/scans/{scan_id}", response_model=list[HostSchema])
def scan_result(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(404)
    return scan.hosts
