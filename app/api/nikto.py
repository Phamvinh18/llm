from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.clients.nikto_client import NiktoClient
from app.core.llm_analyzer import LLMAnalyzer
import time

router = APIRouter()

class NiktoScanRequest(BaseModel):
    target_url: str
    background: bool = True

class NiktoScanId(BaseModel):
    scan_id: str

@router.post('/start')
async def start_nikto_scan(req: NiktoScanRequest):
    """Start Nikto scan"""
    try:
        nikto_client = NiktoClient()
        result = nikto_client.start_scan(req.target_url, background=req.background)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start Nikto scan: {str(e)}")

@router.get('/results/{scan_id}')
async def get_nikto_results(scan_id: str):
    """Get Nikto scan results"""
    try:
        nikto_client = NiktoClient()
        results = nikto_client.get_scan_results(scan_id)
        if results is None:
            raise HTTPException(status_code=404, detail="Scan results not found")
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan results: {str(e)}")

@router.post('/analyze')
async def analyze_nikto_results(req: NiktoScanId):
    """Analyze Nikto results with LLM"""
    try:
        nikto_client = NiktoClient()
        results = nikto_client.get_scan_results(req.scan_id)
        if results is None:
            raise HTTPException(status_code=404, detail="Scan results not found")
        
        # Use LLM to analyze results
        llm_analyzer = LLMAnalyzer()
        analysis = await llm_analyzer.analyze_nikto_results(results)
        
        return {
            'scan_id': req.scan_id,
            'original_results': results,
            'llm_analysis': analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze results: {str(e)}")

@router.get('/scans')
async def list_nikto_scans():
    """List all Nikto scans"""
    try:
        nikto_client = NiktoClient()
        scans = nikto_client.list_scans()
        return {'scans': scans}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list scans: {str(e)}")

@router.post('/scan-and-analyze')
async def scan_and_analyze(req: NiktoScanRequest):
    """Start Nikto scan and return results with LLM analysis"""
    try:
        nikto_client = NiktoClient()
        
        # Start scan (synchronous for immediate results)
        result = nikto_client.start_scan(req.target_url, background=False)
        
        if result.get('status') != 'completed':
            raise HTTPException(status_code=500, detail="Scan failed to complete")
        
        # Analyze with LLM
        llm_analyzer = LLMAnalyzer()
        analysis = await llm_analyzer.analyze_nikto_results(result)
        
        return {
            'scan_id': result['scan_id'],
            'target': req.target_url,
            'findings': result['findings'],
            'summary': result['summary'],
            'llm_analysis': analysis,
            'status': 'completed'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to scan and analyze: {str(e)}")