from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import re, json, os
from app.core.session_store import append_message
from app.core.kb_retriever import KBRetriever
from app.clients import BurpClient, NiktoClient
router = APIRouter()
class IntentRequest(BaseModel):
    session_id: str
    text: str
URL_RE = re.compile(r'(https?://[^\s]+)', re.IGNORECASE)
WHITELIST_PATH = os.getenv('TARGET_WHITELIST_FILE', 'app/data/whitelist.json')

def extract_url(text: str):
    m = URL_RE.search(text)
    return m.group(1).rstrip('.,') if m else None

def load_whitelist():
    if os.path.exists(WHITELIST_PATH):
        try:
            return json.load(open(WHITELIST_PATH,'r',encoding='utf-8'))
        except Exception:
            return []
    return []

def is_whitelisted(url: str):
    wl = load_whitelist()
    for w in wl:
        if url.startswith(w):
            return True
    return False

@router.post('/handle')
def handle(req: IntentRequest):
    text = req.text.strip(); session = req.session_id
    append_message(session, 'user', text)
    if text.lower().startswith(('hãy scan','scan')):
        target = extract_url(text)
        if not target:
            raise HTTPException(status_code=400, detail='Missing target URL')
        if not is_whitelisted(target):
            msg = f'Target {target} not in whitelist'
            append_message(session, 'assistant', msg)
            return {'status':'forbidden','message':msg}
        bc = BurpClient()
        scan_id = bc.start_scan(target)
        try:
            nk = NiktoClient(); nk.start_scan(target, background=True)
        except Exception:
            pass
        msg = {'status':'started','scan_id':scan_id,'target':target}
        append_message(session,'assistant',json.dumps(msg))
        return msg
    kb = KBRetriever()
    docs = kb.retrieve(text, k=5)
    if docs:
        lines = [l.strip() for l in docs[0].get('text','').splitlines() if l.strip()]
        append_message(session,'assistant',json.dumps({'payloads':lines[:40]},ensure_ascii=False))
        return {'payloads':lines[:40],'source':'kb'}
    return {'message':'No payloads found.'}
