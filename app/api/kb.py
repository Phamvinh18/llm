from fastapi import APIRouter, Query
import json, os
router = APIRouter()
KB_FILE = os.path.join(os.path.dirname(__file__),'..','data','payloads_expanded.json')
@router.get('/search')
def kb_search(q: str = Query(...), k: int = 20):
    if not os.path.exists(KB_FILE): return {'results': []}
    data = json.load(open(KB_FILE,'r',encoding='utf-8'))
    results = []
    ql = q.lower()
    for cid,c in data.items():
        for p in c.get('payloads',[]):
            if ql in p.lower() or ql in c.get('notes','').lower():
                results.append({'category':cid,'payload':p,'owasp':c.get('owasp')})
                if len(results)>=k: return {'results':results}
    return {'results': results}
