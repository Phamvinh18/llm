from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import json
from app.core.http_client import HTTPClient, create_curl_command
from app.core.llm_analyzer import LLMAnalyzer
from app.core.payload_suggester import suggest_payloads, get_payloads_by_type, get_all_vulnerability_types

router = APIRouter()


class AttackRequest(BaseModel):
    url: str
    payload: str
    parameter: str = 'q'
    method: str = 'GET'
    headers: Optional[Dict[str, str]] = None
    session_id: str


class PayloadRequest(BaseModel):
    vulnerability_type: str
    target_url: Optional[str] = None
    parameter: str = 'q'
    session_id: str


class VulnerabilityTypesResponse(BaseModel):
    vulnerability_types: List[str]


@router.post('/send-payload')
async def send_payload(request: AttackRequest) -> Dict[str, Any]:
    """
    Send a payload to target URL and analyze the response with enhanced analysis
    """
    try:
        client = HTTPClient()
        
        # Send the payload
        response_data = client.test_payload(
            base_url=request.url,
            payload=request.payload,
            parameter=request.parameter,
            method=request.method,
            headers=request.headers
        )
        
        # Analyze the response
        analysis = client.analyze_response(response_data)
        
        # Generate curl command
        curl_command = create_curl_command(response_data)
        
        # Enhanced LLM analysis for attack response
        llm_analyzer = LLMAnalyzer()
        llm_analysis = None
        
        if response_data.get('success', False):
            # Comprehensive LLM analysis
            llm_analysis = llm_analyzer.analyze_response(
                response_data=response_data,
                payload=request.payload,
                vulnerability_type=getattr(request, 'vulnerability_type', None)
            )
        
        # Enhanced vulnerability detection with LLM
        vulnerability_detected = False
        vulnerability_type = "Unknown"
        confidence_score = 0.0
        detailed_findings = []
        
        if llm_analysis:
            confidence_score = llm_analysis.get('confidence', 0.0)
            vulnerability_type = llm_analysis.get('vulnerability_type', 'Unknown')
            vulnerability_detected = llm_analysis.get('vulnerability_detected', False)
            
            # Extract detailed findings from LLM
            detailed_findings = {
                'description': llm_analysis.get('description', ''),
                'evidence': llm_analysis.get('evidence', []),
                'exploitation_steps': llm_analysis.get('exploitation_steps', []),
                'remediation': llm_analysis.get('remediation', ''),
                'risk_assessment': llm_analysis.get('risk_assessment', ''),
                'false_positive_indicators': llm_analysis.get('false_positive_indicators', [])
            }
        
        # Fallback to heuristic detection if LLM analysis is not available
        if not vulnerability_detected:
            vulnerability_detected, vulnerability_type = _detect_vulnerability_indicators(
                response_data, request.payload
            )
            if vulnerability_detected:
                confidence_score = 0.6  # Medium confidence for heuristic detection
        
        # Generate comprehensive exploitation guide
        exploitation_guide = _generate_comprehensive_exploitation_guide(
            vulnerability_type, request.payload, request.url, response_data, llm_analysis
        )
        
        return {
            'success': True,
            'response': response_data,
            'analysis': analysis,
            'llm_analysis': llm_analysis,
            'curl_command': curl_command,
            'payload_used': request.payload,
            'parameter': request.parameter,
            'method': request.method,
            'vulnerability_detected': vulnerability_detected,
            'vulnerability_type': vulnerability_type,
            'confidence_score': confidence_score,
            'detailed_findings': detailed_findings,
            'exploitation_guide': exploitation_guide,
            'risk_level': _assess_risk_level(vulnerability_type, confidence_score)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack failed: {str(e)}")


def _detect_vulnerability_indicators(response_data: Dict[str, Any], payload: str):
    """
    Detect vulnerability indicators in response
    """
    if not response_data.get('success', False):
        return False, "Unknown"
    
    body = response_data.get('body', '').lower()
    status_code = response_data.get('status_code', 0)
    headers = response_data.get('headers', {})
    
    # SQL Injection indicators
    sql_errors = [
        'sql error', 'mysql error', 'postgresql error', 'oracle error',
        'database error', 'syntax error', 'sqlite error'
    ]
    if any(error in body for error in sql_errors):
        return True, "SQL Injection"
    
    # XSS indicators
    if '<script>' in payload.lower() and payload.lower() in body:
        return True, "Cross-Site Scripting"
    
    # Path Traversal indicators
    if 'root:x:0:0:root' in body or 'bin:x:1:1:bin' in body:
        return True, "Path Traversal"
    
    # Command Injection indicators
    if 'uid=' in body and 'gid=' in body:
        return True, "Command Injection"
    
    # Information Disclosure
    if status_code == 200 and any(keyword in body for keyword in ['error', 'exception', 'stack trace']):
        return True, "Information Disclosure"
    
    # Missing Security Headers
    security_headers = ['x-frame-options', 'x-content-type-options', 'x-xss-protection']
    if not any(header in headers for header in security_headers):
        return True, "Security Misconfiguration"
    
    return False, "Unknown"


def _generate_comprehensive_exploitation_guide(vulnerability_type: str, payload: str, url: str, response_data: Dict[str, Any], llm_analysis: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Generate comprehensive exploitation guide with LLM insights
    """
    guide = {
        'overview': f'Exploitation guide for {vulnerability_type} vulnerability',
        'steps': [],
        'tools': [],
        'payloads': [payload],
        'mitigation': [],
        'next_steps': []
    }
    
    # Use LLM analysis if available
    if llm_analysis and llm_analysis.get('exploitation_steps'):
        guide['steps'] = llm_analysis['exploitation_steps']
        guide['mitigation'] = [llm_analysis.get('remediation', '')]
    else:
        # Fallback to basic exploitation steps
        guide['steps'] = _generate_exploitation_steps(vulnerability_type, payload, url)
    
    # Add tools based on vulnerability type
    if vulnerability_type == "SQL Injection":
        guide['tools'] = ["SQLMap", "Burp Suite", "NoSQLMap", "Havij"]
        guide['next_steps'] = [
            "Extract database schema",
            "Enumerate tables and columns", 
            "Extract sensitive data",
            "Test for privilege escalation"
        ]
    elif vulnerability_type == "Cross-Site Scripting":
        guide['tools'] = ["Burp Suite", "XSS Hunter", "BeEF", "XSStrike"]
        guide['next_steps'] = [
            "Test for stored XSS",
            "Bypass filters and WAF",
            "Steal session cookies",
            "Perform actions on behalf of users"
        ]
    elif vulnerability_type == "Path Traversal":
        guide['tools'] = ["Burp Suite", "Dirb", "Gobuster", "wfuzz"]
        guide['next_steps'] = [
            "Access system files",
            "Read application source code",
            "Look for configuration files",
            "Search for credentials"
        ]
    elif vulnerability_type == "Command Injection":
        guide['tools'] = ["Burp Suite", "Metasploit", "Netcat", "Reverse shells"]
        guide['next_steps'] = [
            "Establish reverse shell",
            "Enumerate system information",
            "Escalate privileges",
            "Maintain persistence"
        ]
    else:
        guide['tools'] = ["Burp Suite", "Custom scripts", "Manual testing"]
        guide['next_steps'] = [
            "Further reconnaissance",
            "Test additional attack vectors",
            "Document findings"
        ]
    
    # Add response-specific insights
    if response_data.get('status_code') == 200:
        guide['response_analysis'] = "Target responded successfully - vulnerability likely exploitable"
    elif response_data.get('status_code') in [500, 502, 503]:
        guide['response_analysis'] = "Server error - may indicate successful exploitation"
    else:
        guide['response_analysis'] = f"Response code {response_data.get('status_code')} - requires further analysis"
    
    return guide


def _generate_exploitation_steps(vulnerability_type: str, payload: str, url: str) -> List[str]:
    """
    Generate exploitation steps based on vulnerability type
    """
    steps = []
    
    if vulnerability_type == "SQL Injection":
        steps = [
            f"1. Confirm SQL injection with payload: {payload}",
            "2. Identify database type from error messages",
            "3. Extract database schema using UNION queries",
            "4. Extract sensitive data (users, passwords, etc.)",
            "5. Consider privilege escalation if possible"
        ]
    elif vulnerability_type == "Cross-Site Scripting":
        steps = [
            f"1. Confirm XSS with payload: {payload}",
            "2. Test different XSS payloads for bypass",
            "3. Create persistent XSS if possible",
            "4. Steal session cookies or credentials",
            "5. Perform actions on behalf of users"
        ]
    elif vulnerability_type == "Path Traversal":
        steps = [
            f"1. Confirm path traversal with payload: {payload}",
            "2. Try different path traversal techniques",
            "3. Access sensitive files (/etc/passwd, config files)",
            "4. Look for application source code",
            "5. Search for credentials in configuration files"
        ]
    elif vulnerability_type == "Command Injection":
        steps = [
            f"1. Confirm command injection with payload: {payload}",
            "2. Identify operating system type",
            "3. Execute system commands (whoami, id, pwd)",
            "4. Enumerate system information",
            "5. Attempt privilege escalation"
        ]
    else:
        steps = [
            f"1. Verify vulnerability with payload: {payload}",
            "2. Gather more information about the application",
            "3. Look for additional attack vectors",
            "4. Document findings for remediation"
        ]
    
    return steps


def _assess_risk_level(vulnerability_type: str, confidence_score: float) -> str:
    """
    Assess risk level based on vulnerability type and confidence
    """
    high_risk_vulns = ["SQL Injection", "Command Injection", "Path Traversal"]
    medium_risk_vulns = ["Cross-Site Scripting", "Information Disclosure"]
    
    if vulnerability_type in high_risk_vulns and confidence_score > 0.7:
        return "Critical"
    elif vulnerability_type in high_risk_vulns or (vulnerability_type in medium_risk_vulns and confidence_score > 0.7):
        return "High"
    elif vulnerability_type in medium_risk_vulns or confidence_score > 0.5:
        return "Medium"
    else:
        return "Low"


@router.post('/get-payloads')
async def get_payloads(request: PayloadRequest) -> Dict[str, Any]:
    """
    Get payloads for a specific vulnerability type
    """
    try:
        if request.vulnerability_type.lower() == 'all':
            # Return all vulnerability types
            vuln_types = get_all_vulnerability_types()
            return {
                'vulnerability_types': vuln_types,
                'message': 'Available vulnerability types'
            }
        
        # Get payloads for specific vulnerability type
        payloads_data = get_payloads_by_type(request.vulnerability_type)
        
        if not payloads_data:
            raise HTTPException(
                status_code=404, 
                detail=f"Vulnerability type '{request.vulnerability_type}' not found"
            )
        
        # If target URL is provided, generate full URLs with payloads
        if request.target_url:
            from app.core.payload_suggester import suggest_payloads
            baseline_finding = {
                'title': request.vulnerability_type,
                'url': request.target_url,
                'parameter': request.parameter
            }
            suggestions = suggest_payloads(baseline_finding, request.vulnerability_type)
            return {
                'vulnerability_type': request.vulnerability_type,
                'payloads_data': payloads_data,
                'suggestions': suggestions,
                'target_url': request.target_url,
                'parameter': request.parameter
            }
        else:
            return {
                'vulnerability_type': request.vulnerability_type,
                'payloads_data': payloads_data
            }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get payloads: {str(e)}")


@router.get('/vulnerability-types')
async def get_vulnerability_types() -> VulnerabilityTypesResponse:
    """
    Get all available vulnerability types
    """
    try:
        vuln_types = get_all_vulnerability_types()
        return VulnerabilityTypesResponse(vulnerability_types=vuln_types)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get vulnerability types: {str(e)}")


@router.post('/analyze-response')
async def analyze_response(response_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a response for potential vulnerabilities using LLM
    """
    try:
        llm_analyzer = LLMAnalyzer()
        
        analysis = llm_analyzer.analyze_response(
            response_data=response_data,
            payload=response_data.get('payload', ''),
            vulnerability_type=response_data.get('vulnerability_type')
        )
        
        return {
            'success': True,
            'analysis': analysis
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post('/compare-responses')
async def compare_responses(original: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two responses to detect differences
    """
    try:
        client = HTTPClient()
        comparison = client.compare_responses(original, payload)
        
        return {
            'success': True,
            'comparison': comparison
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Comparison failed: {str(e)}")
