"""
API endpoints for Chat Assistant RAG System
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from app.core.chat_assistant_rag import ChatAssistantRAG, ChatResponse

router = APIRouter()

class ChatMessage(BaseModel):
    message: str
    user_id: Optional[str] = "default"

class ChatResponseModel(BaseModel):
    success: bool
    response: Dict[str, Any]
    processing_time: float

@router.post('/chat', response_model=ChatResponseModel)
async def chat_with_assistant(message: ChatMessage):
    """
    Chat với Chat Assistant RAG System
    """
    try:
        import time
        start_time = time.time()
        
        # Initialize chat assistant
        chat_assistant = ChatAssistantRAG()
        
        # Process message
        response = await chat_assistant.process_message(
            user_message=message.message,
            user_id=message.user_id
        )
        
        processing_time = time.time() - start_time
        
        # Convert ChatResponse to dict
        response_dict = {
            "message": response.message,
            "command": response.command.value,
            "vulnerability_type": response.vulnerability_type.value if response.vulnerability_type else None,
            "target_url": response.target_url,
            "payloads": response.payloads,
            "scan_results": response.scan_results,
            "llm_analysis": response.llm_analysis,
            "suggestions": response.suggestions
        }
        
        return ChatResponseModel(
            success=True,
            response=response_dict,
            processing_time=processing_time
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat processing failed: {str(e)}")

@router.post('/payload')
async def generate_payloads(message: ChatMessage):
    """
    Generate payloads cho lỗ hổng
    """
    try:
        chat_assistant = ChatAssistantRAG()
        
        # Process payload command
        response = await chat_assistant.process_message(f"/payload {message.message}")
        
        return {
            "success": True,
            "command": "payload",
            "vulnerability_type": response.vulnerability_type.value if response.vulnerability_type else None,
            "target_url": response.target_url,
            "payloads": response.payloads,
            "message": response.message,
            "suggestions": response.suggestions
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payload generation failed: {str(e)}")

@router.post('/scan')
async def scan_target(message: ChatMessage):
    """
    Scan target URL
    """
    try:
        chat_assistant = ChatAssistantRAG()
        
        # Process scan command
        response = await chat_assistant.process_message(f"/scan {message.message}")
        
        return {
            "success": True,
            "command": "scan",
            "target_url": response.target_url,
            "scan_results": response.scan_results,
            "llm_analysis": response.llm_analysis,
            "message": response.message,
            "suggestions": response.suggestions
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get('/help')
async def get_help():
    """
    Get help information
    """
    try:
        chat_assistant = ChatAssistantRAG()
        
        # Get help response
        response = await chat_assistant.process_message("/help")
        
        return {
            "success": True,
            "help_message": response.message,
            "suggestions": response.suggestions
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Help failed: {str(e)}")

@router.get('/health')
async def health_check():
    """
    Health check for Chat Assistant
    """
    try:
        return {
            "status": "healthy",
            "service": "Chat Assistant RAG",
            "features": [
                "Vulnerability RAG with URLs",
                "Payload generation",
                "Scan and analysis",
                "Natural conversation",
                "Slash commands",
                "LLM analysis"
            ],
            "supported_vulnerabilities": [
                "XSS - Cross-Site Scripting",
                "SQL Injection",
                "Security Misconfiguration",
                "IDOR - Insecure Direct Object Reference"
            ],
            "supported_commands": [
                "/payload - Generate payloads",
                "/scan - Scan and analyze",
                "/help - Show help",
                "/ - Greeting"
            ]
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "service": "Chat Assistant RAG",
            "error": str(e)
        }

@router.get('/examples')
async def get_examples():
    """
    Get usage examples
    """
    try:
        return {
            "success": True,
            "examples": {
                "payload_commands": [
                    "/payload xss http://testphp.vulnweb.com",
                    "/payload sql_injection http://demo.testfire.net",
                    "/payload misconfig http://httpbin.org",
                    "/payload idor http://example.com"
                ],
                "scan_commands": [
                    "/scan http://testphp.vulnweb.com",
                    "/scan http://demo.testfire.net",
                    "/scan http://httpbin.org",
                    "/scan http://example.com"
                ],
                "natural_conversation": [
                    "Tạo payload XSS cho http://testphp.vulnweb.com",
                    "Scan lỗ hổng http://demo.testfire.net",
                    "Hướng dẫn sử dụng",
                    "Xin chào"
                ],
                "vulnerability_types": [
                    "xss - Cross-Site Scripting",
                    "sql_injection - SQL Injection",
                    "misconfig - Security Misconfiguration",
                    "idor - Insecure Direct Object Reference"
                ]
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get examples: {str(e)}")

@router.get('/vulnerabilities')
async def get_vulnerability_info():
    """
    Get vulnerability information from RAG
    """
    try:
        chat_assistant = ChatAssistantRAG()
        vulnerability_rag = chat_assistant.vulnerability_rag
        
        return {
            "success": True,
            "vulnerabilities": {
                "xss": {
                    "title": vulnerability_rag.get('vulnerability_knowledge', {}).get('xss', {}).get('title', 'XSS'),
                    "description": vulnerability_rag.get('vulnerability_knowledge', {}).get('xss', {}).get('description', ''),
                    "types": list(vulnerability_rag.get('vulnerability_knowledge', {}).get('xss', {}).get('types', {}).keys())
                },
                "sql_injection": {
                    "title": vulnerability_rag.get('vulnerability_knowledge', {}).get('sql_injection', {}).get('title', 'SQL Injection'),
                    "description": vulnerability_rag.get('vulnerability_knowledge', {}).get('sql_injection', {}).get('description', ''),
                    "types": list(vulnerability_rag.get('vulnerability_knowledge', {}).get('sql_injection', {}).get('types', {}).keys())
                },
                "misconfiguration": {
                    "title": vulnerability_rag.get('vulnerability_knowledge', {}).get('misconfiguration', {}).get('title', 'Security Misconfiguration'),
                    "description": vulnerability_rag.get('vulnerability_knowledge', {}).get('misconfiguration', {}).get('description', ''),
                    "types": list(vulnerability_rag.get('vulnerability_knowledge', {}).get('misconfiguration', {}).get('types', {}).keys())
                },
                "idor": {
                    "title": vulnerability_rag.get('vulnerability_knowledge', {}).get('idor', {}).get('title', 'IDOR'),
                    "description": vulnerability_rag.get('vulnerability_knowledge', {}).get('idor', {}).get('description', ''),
                    "types": list(vulnerability_rag.get('vulnerability_knowledge', {}).get('idor', {}).get('types', {}).keys())
                }
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get vulnerability info: {str(e)}")
