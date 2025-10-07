from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from app.core.heuristics import run_rules
from app.core.llm_analyzer import LLMAnalyzer


router = APIRouter()


class HTTPMessage(BaseModel):
    method: Optional[str] = None
    url: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    body: Optional[str] = None
    status: Optional[int] = None


class AnalyzeInput(BaseModel):
    request: Optional[HTTPMessage] = None
    response: HTTPMessage
    history: Optional[List[Dict[str, Any]]] = None


@router.post('/analyze')
def analyze(inp: AnalyzeInput):
    payload = {
        'request': (inp.request.dict() if inp.request else {}),
        'response': inp.response.dict(),
        'history': inp.history or [],
    }
    facts = run_rules(payload)
    payload['heuristics'] = facts
    finding = LLMAnalyzer().analyze(payload)
    # Cross-check simple claims
    if any(f.get('type') == 'header_missing' and f.get('name') == 'Content-Security-Policy' for f in facts):
        pass
    return {'facts': facts, 'finding': finding}


