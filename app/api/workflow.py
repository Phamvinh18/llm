from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import time
from app.clients import BurpClient, NiktoClient
from app.core.burp_analyzer import BurpFindingAnalyzer
from app.core.session_store import append_message
from app.core.payload_suggester import suggest_payloads, augment_with_llm


router = APIRouter()


class ScanRequest(BaseModel):
    target_url: str
    session_id: Optional[str] = None


class AnalysisRequest(BaseModel):
    scan_id: str
    session_id: Optional[str] = None


class WorkflowRequest(BaseModel):
    target_url: str
    session_id: Optional[str] = None
    auto_analyze: bool = True


@router.post('/scan-and-analyze')
def scan_and_analyze(req: WorkflowRequest):
    """
    Complete workflow: Start Burp scan -> Wait for results -> Analyze with LLM -> Generate curl tests
    """
    try:
        # Start Burp scan
        burp_client = BurpClient()
        scan_id = burp_client.start_scan(req.target_url)

        # Kick off Nikto in background (best-effort)
        try:
            NiktoClient().start_scan(req.target_url, background=True)
        except Exception:
            pass
        
        # Wait a moment for scan to complete (in real implementation, this would be async)
        time.sleep(2)
        
        # Get scan results
        scan_details = burp_client.get_scan_details(scan_id)
        if not scan_details:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Enhanced LLM analysis of Burp findings
        from app.core.llm_analyzer import LLMAnalyzer
        llm_analyzer = LLMAnalyzer()
        
        # Analyze each finding with LLM
        enhanced_findings = []
        for finding in scan_details.get('issues', []):
            # LLM analysis for each finding
            llm_analysis = llm_analyzer.analyze_response(
                response_data=finding.get('response', {}),
                payload=finding.get('request', {}).get('body', '') or finding.get('url', ''),
                vulnerability_type=finding.get('title', '')
            )
            
            # Enhanced finding with LLM insights
            enhanced_finding = {
                **finding,
                'llm_analysis': llm_analysis,
                'confidence_score': llm_analysis.get('confidence', 0.5) if llm_analysis else 0.5,
                'exploitation_potential': llm_analysis.get('exploitation_potential', 'Medium') if llm_analysis else 'Medium',
                'detailed_description': llm_analysis.get('description', finding.get('recommendation', '')) if llm_analysis else finding.get('recommendation', ''),
                'false_positive_risk': llm_analysis.get('false_positive_indicators', []) if llm_analysis else []
            }
            
            # Add payload suggestions
            base = {
                'title': finding.get('title'),
                'url': finding.get('url'),
                'parameter': finding.get('parameter'),
                'request': finding.get('request'),
                'response': finding.get('response'),
            }
            base_suggestions = suggest_payloads(base)
            llm_suggestions = augment_with_llm({'request': base.get('request'), 'response': base.get('response'), 'title': base.get('title')}) or []
            enhanced_finding['suggested_payloads'] = (base_suggestions + llm_suggestions)[:10]
            
            enhanced_findings.append(enhanced_finding)
        
        # Create comprehensive analysis results
        analysis_results = {
            'findings': enhanced_findings,
            'summary': {
                'total_findings': len(enhanced_findings),
                'critical_count': len([f for f in enhanced_findings if f.get('risk') == 'Critical']),
                'high_count': len([f for f in enhanced_findings if f.get('risk') == 'High']),
                'medium_count': len([f for f in enhanced_findings if f.get('risk') == 'Medium']),
                'low_count': len([f for f in enhanced_findings if f.get('risk') == 'Low']),
                'overall_risk': _calculate_overall_risk(enhanced_findings),
                'llm_analyzed': True
            }
        }
        
        # Store in session if provided
        if req.session_id:
            append_message(req.session_id, 'assistant', f"Scan completed for {req.target_url}. Found {analysis_results['summary']['total_findings']} issues.")
        
        return {
            'scan_id': scan_id,
            'target': req.target_url,
            'status': 'completed',
            'analysis': analysis_results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Workflow failed: {str(e)}")


@router.post('/scan')
def start_scan(req: ScanRequest):
    """
    Start a new Burp scan
    """
    try:
        burp_client = BurpClient()
        scan_id = burp_client.start_scan(req.target_url)
        
        if req.session_id:
            append_message(req.session_id, 'assistant', f"Started scan for {req.target_url}. Scan ID: {scan_id}")
        
        return {
            'scan_id': scan_id,
            'target': req.target_url,
            'status': 'started',
            'message': 'Scan started successfully'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@router.get('/scan/{scan_id}/status')
def get_scan_status(scan_id: str):
    """
    Get scan status and basic info
    """
    try:
        burp_client = BurpClient()
        scan_details = burp_client.get_scan_details(scan_id)
        
        if not scan_details:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        issues = scan_details.get('issues', [])
        summary = {
            'scan_id': scan_id,
            'target': scan_details.get('target'),
            'started_at': scan_details.get('started_at'),
            'total_findings': len(issues),
            'risk_breakdown': {
                'Critical': len([i for i in issues if i.get('risk') == 'Critical']),
                'High': len([i for i in issues if i.get('risk') == 'High']),
                'Medium': len([i for i in issues if i.get('risk') == 'Medium']),
                'Low': len([i for i in issues if i.get('risk') == 'Low'])
            }
        }
        
        return summary
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")


@router.post('/analyze-scan')
def analyze_scan(req: AnalysisRequest):
    """
    Analyze existing scan results with LLM
    """
    try:
        burp_client = BurpClient()
        scan_details = burp_client.get_scan_details(req.scan_id)
        
        if not scan_details:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Analyze with LLM
        analyzer = BurpFindingAnalyzer()
        analysis_results = analyzer.analyze_scan_results(scan_details)
        
        if req.session_id:
            append_message(req.session_id, 'assistant', f"Analysis completed for scan {req.scan_id}")
        
        return {
            'scan_id': req.scan_id,
            'analysis': analysis_results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get('/scan/{scan_id}/findings')
def get_scan_findings(scan_id: str, analyzed: bool = False):
    """
    Get scan findings, optionally with LLM analysis
    """
    try:
        burp_client = BurpClient()
        scan_details = burp_client.get_scan_details(scan_id)
        
        if not scan_details:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        if analyzed:
            # Return with LLM analysis
            analyzer = BurpFindingAnalyzer()
            analysis_results = analyzer.analyze_scan_results(scan_details)
            return analysis_results
        else:
            # Return raw findings
            return scan_details
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get findings: {str(e)}")


@router.get('/scan/{scan_id}/curl/{finding_id}')
def get_curl_commands(scan_id: str, finding_id: str):
    """
    Get curl commands for testing a specific finding
    """
    try:
        burp_client = BurpClient()
        scan_details = burp_client.get_scan_details(scan_id)
        
        if not scan_details:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Find the specific finding
        finding = None
        for issue in scan_details.get('issues', []):
            if issue.get('id') == finding_id:
                finding = issue
                break
        
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        
        # Generate curl commands
        from app.core.curl_generator import generate_test_curl_commands, generate_curl_for_verification
        
        curl_commands = generate_test_curl_commands(finding)
        verification_curl = generate_curl_for_verification(finding, 'basic')
        
        return {
            'finding_id': finding_id,
            'finding_title': finding.get('title'),
            'curl_commands': curl_commands,
            'verification_curl': verification_curl
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate curl commands: {str(e)}")


@router.get('/scan/{scan_id}/payloads/{finding_id}')
def get_suggested_payloads(scan_id: str, finding_id: str):
    try:
        burp_client = BurpClient()
        scan_details = burp_client.get_scan_details(scan_id)
        if not scan_details:
            raise HTTPException(status_code=404, detail="Scan not found")
        # locate finding
        finding = None
        for issue in scan_details.get('issues', []):
            if issue.get('id') == finding_id:
                finding = issue
                break
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        base_suggestions = suggest_payloads(finding)
        llm_suggestions = augment_with_llm({'request': finding.get('request'), 'response': finding.get('response'), 'title': finding.get('title')}) or []
        return {'finding_id': finding_id, 'suggested_payloads': (base_suggestions + llm_suggestions)[:10]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to suggest payloads: {str(e)}")


@router.get('/scans')
def list_scans():
    """
    List all available scans
    """
    try:
        import os
        import json
        # Import BurpClient locally to avoid redefinition
        
        burp_client = BurpClient()
        scan_dir = burp_client.scan_dir
        
        scans = []
        if os.path.exists(scan_dir):
            for filename in os.listdir(scan_dir):
                if filename.endswith('.json'):
                    scan_id = filename[:-5]  # Remove .json extension
                    try:
                        with open(os.path.join(scan_dir, filename), 'r', encoding='utf-8') as f:
                            scan_data = json.load(f)
                            scans.append({
                                'scan_id': scan_id,
                                'target': scan_data.get('target'),
                                'started_at': scan_data.get('started_at'),
                                'total_findings': len(scan_data.get('issues', []))
                            })
                    except Exception:
                        continue
        
        return {'scans': scans}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list scans: {str(e)}")


def _calculate_overall_risk(findings: List[Dict[str, Any]]) -> str:
    """
    Calculate overall risk level based on findings
    """
    if not findings:
        return 'Low'
    
    # Count findings by risk level
    risk_counts = {
        'Critical': len([f for f in findings if f.get('risk') == 'Critical']),
        'High': len([f for f in findings if f.get('risk') == 'High']),
        'Medium': len([f for f in findings if f.get('risk') == 'Medium']),
        'Low': len([f for f in findings if f.get('risk') == 'Low'])
    }
    
    # Determine overall risk
    if risk_counts['Critical'] > 0:
        return 'Critical'
    elif risk_counts['High'] > 0:
        return 'High'
    elif risk_counts['Medium'] > 0:
        return 'Medium'
    else:
        return 'Low'
