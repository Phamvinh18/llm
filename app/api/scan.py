from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.clients import BurpClient
router = APIRouter()
class ScanStartRequest(BaseModel):
    session_id: str
    target_url: str
class ScanId(BaseModel):
    scan_id: str
@router.post('/start')
def start_scan(req: ScanStartRequest):
    bc = BurpClient(); sid = bc.start_scan(req.target_url); return {'scan_id': sid}
@router.post('/issues')
def get_issues(req: ScanId):
    bc = BurpClient(); issues = bc.get_issues(req.scan_id); return {'findings': issues}
