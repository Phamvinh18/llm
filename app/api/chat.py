from fastapi import APIRouter
from pydantic import BaseModel
from app.core.rag_assistant import RAGAssistant
from app.core.session_store import get_history
router = APIRouter()
class ChatRequest(BaseModel):
    session_id: str
    message: str
    target: str = None
@router.post('/message')
def message(req: ChatRequest):
    assistant = RAGAssistant()
    answer = assistant.answer(req.session_id, req.message, target=req.target)
    try:
        import json
        parsed = json.loads(answer)
    except Exception:
        parsed = None
    history = get_history(req.session_id, limit=20)
    return {'answer': parsed or answer, 'history': history}
