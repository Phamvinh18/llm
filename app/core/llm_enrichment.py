"""
LLM Enrichment - Enhanced RAG + LLM for vulnerability analysis
"""

import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from app.core.enhanced_rag_retriever import EnhancedRAGRetriever
from app.clients.gemini_client import GeminiClient
from app.core.tool_parsers import NormalizedFinding

@dataclass
class EnrichedFinding:
    id: str
    type: str
    short_summary: str
    severity: str
    confidence: str
    justification: str
    cvss_v3: str
    safe_poc_steps: List[str]
    remediation: List[str]
    references: List[str]
    raw_evidence: str
    rag_context: str

class LLMEnrichment:
    def __init__(self):
        self.rag_retriever = EnhancedRAGRetriever()
        self.llm_client = GeminiClient()
    
    async def enrich_findings(self, findings: List[NormalizedFinding], job_id: str) -> List[EnrichedFinding]:
        """Enrich findings with RAG + LLM analysis"""
        enriched_findings = []
        
        for finding in findings:
            try:
                # Get RAG context for this finding
                rag_context = self._get_rag_context_for_finding(finding)
                
                # Generate LLM analysis
                llm_analysis = await self._analyze_finding_with_llm(finding, rag_context)
                
                # Create enriched finding
                enriched = EnrichedFinding(
                    id=finding.id,
                    type=finding.type,
                    short_summary=llm_analysis.get('short_summary', finding.type),
                    severity=llm_analysis.get('severity', finding.severity),
                    confidence=llm_analysis.get('confidence', finding.confidence),
                    justification=llm_analysis.get('justification', ''),
                    cvss_v3=llm_analysis.get('cvss_v3', finding.cvss_v3 or '0.0'),
                    safe_poc_steps=llm_analysis.get('safe_poc_steps', finding.safe_poc_steps),
                    remediation=llm_analysis.get('remediation', finding.remediation),
                    references=llm_analysis.get('references', []),
                    raw_evidence=finding.evidence_snippet,
                    rag_context=rag_context
                )
                
                enriched_findings.append(enriched)
                
            except Exception as e:
                print(f"Error enriching finding {finding.id}: {e}")
                # Create fallback enriched finding
                enriched = EnrichedFinding(
                    id=finding.id,
                    type=finding.type,
                    short_summary=f"Vulnerability found: {finding.type}",
                    severity=finding.severity,
                    confidence=finding.confidence,
                    justification="Analysis failed, using basic information",
                    cvss_v3=finding.cvss_v3 or '0.0',
                    safe_poc_steps=finding.safe_poc_steps,
                    remediation=finding.remediation,
                    references=[],
                    raw_evidence=finding.evidence_snippet,
                    rag_context=""
                )
                enriched_findings.append(enriched)
        
        return enriched_findings
    
    def _get_rag_context_for_finding(self, finding: NormalizedFinding) -> str:
        """Get RAG context for a specific finding"""
        context_parts = []
        
        # Get vulnerability-specific knowledge
        vuln_info = self.rag_retriever.get_vulnerability_info(finding.type.lower().replace('-', '_'))
        if vuln_info:
            context_parts.append(f"""
**VULNERABILITY KNOWLEDGE:**
- Type: {finding.type}
- Description: {vuln_info.get('description', 'N/A')}
- CVSS Score: {vuln_info.get('cvss_score', 'N/A')}
- CWE: {vuln_info.get('cwe', 'N/A')}
- OWASP Top 10: {vuln_info.get('owasp_top10', 'N/A')}
- Attack Complexity: {vuln_info.get('attack_complexity', 'N/A')}
- Impact: {vuln_info.get('impact', 'N/A')}
- Detection Methods: {', '.join(vuln_info.get('detection_methods', []))}
- Remediation: {vuln_info.get('remediation', 'N/A')}
""")
        
        # Get payload information
        payloads = self.rag_retriever.get_payloads(finding.type.lower().replace('-', '_'))
        if payloads:
            context_parts.append(f"""
**PAYLOAD INFORMATION:**
- Available payloads: {len(payloads)} types
- Categories: {', '.join(payloads.keys()) if isinstance(payloads, dict) else 'Basic payloads available'}
""")
        
        # Get remediation guide
        remediation_guide = self.rag_retriever.get_remediation_guide(finding.type.lower().replace('-', '_'))
        if remediation_guide:
            context_parts.append(f"""
**REMEDIATION GUIDE:**
- Prevention: {remediation_guide.get('prevention', 'N/A')}
- Detection: {remediation_guide.get('detection', 'N/A')}
- Response: {remediation_guide.get('response', 'N/A')}
""")
        
        # Get error patterns if applicable
        if 'sql' in finding.type.lower():
            error_patterns = self.rag_retriever.get_error_patterns('mysql')
            if error_patterns:
                context_parts.append(f"""
**SQL ERROR PATTERNS:**
- Common MySQL errors: {len(error_patterns)} patterns
- Detection methods: Error message analysis, behavior changes
""")
        
        return "\n".join(context_parts)
    
    async def _analyze_finding_with_llm(self, finding: NormalizedFinding, rag_context: str) -> Dict[str, Any]:
        """Analyze finding with LLM using RAG context"""
        
        prompt = f"""
You are a senior web security engineer. Analyze the following vulnerability finding and provide structured output.

**FINDING INFORMATION:**
- ID: {finding.id}
- Type: {finding.type}
- Path: {finding.path}
- Parameter: {finding.parameter or 'N/A'}
- Tool: {finding.tool}
- Evidence: {finding.evidence_snippet[:500]}...

**RAG CONTEXT:**
{rag_context}

**TASK:**
Provide analysis in the following JSON format:
{{
    "short_summary": "Brief 1-2 sentence summary of the vulnerability",
    "severity": "Critical|High|Medium|Low|Info",
    "confidence": "High|Medium|Low",
    "justification": "Detailed explanation of severity and confidence assessment",
    "cvss_v3": "CVSS v3.1 score (e.g., 7.5)",
    "safe_poc_steps": ["Step 1", "Step 2", "Step 3", "Step 4"],
    "remediation": ["Remediation step 1", "Remediation step 2", "Remediation step 3"],
    "references": ["Reference 1", "Reference 2"]
}}

**RULES:**
1. Use ONLY provided evidence and RAG context to justify severity/confidence
2. Provide non-destructive PoC steps
3. Provide specific, actionable remediation steps
4. Do NOT invent facts not present in evidence
5. Be conservative with severity assessment
6. Include relevant OWASP/CWE references when applicable

**EVIDENCE ANALYSIS:**
Focus on:
- What the evidence shows
- How the vulnerability can be exploited
- What the potential impact is
- How confident you are in the assessment

Respond with ONLY the JSON object, no additional text.
"""
        
        try:
            response = await self.llm_client.chat(prompt)
            
            # Try to parse JSON response
            try:
                # Extract JSON from response
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                
                if json_start != -1 and json_end != -1:
                    json_str = response[json_start:json_end]
                    analysis = json.loads(json_str)
                    
                    # Validate required fields
                    required_fields = ['short_summary', 'severity', 'confidence', 'justification']
                    for field in required_fields:
                        if field not in analysis:
                            analysis[field] = 'N/A'
                    
                    return analysis
                else:
                    raise ValueError("No JSON found in response")
                    
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Error parsing LLM JSON response: {e}")
                return self._create_fallback_analysis(finding)
                
        except Exception as e:
            print(f"Error calling LLM: {e}")
            return self._create_fallback_analysis(finding)
    
    def _create_fallback_analysis(self, finding: NormalizedFinding) -> Dict[str, Any]:
        """Create fallback analysis when LLM fails"""
        return {
            "short_summary": f"Vulnerability detected: {finding.type} at {finding.path}",
            "severity": finding.severity,
            "confidence": finding.confidence,
            "justification": "LLM analysis failed, using basic assessment",
            "cvss_v3": finding.cvss_v3 or "0.0",
            "safe_poc_steps": finding.safe_poc_steps,
            "remediation": finding.remediation,
            "references": []
        }
    
    async def generate_scan_summary(self, enriched_findings: List[EnrichedFinding], target_url: str, scan_profile: str) -> Dict[str, Any]:
        """Generate comprehensive scan summary"""
        
        # Count findings by severity
        severity_counts = {}
        for finding in enriched_findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Get top findings
        top_findings = sorted(enriched_findings, key=lambda x: self._severity_to_score(x.severity), reverse=True)[:5]
        
        # Generate LLM summary
        summary_prompt = f"""
You are a senior security consultant. Provide a comprehensive security assessment summary.

**SCAN DETAILS:**
- Target: {target_url}
- Profile: {scan_profile}
- Total Findings: {len(enriched_findings)}

**FINDINGS BY SEVERITY:**
{json.dumps(severity_counts, indent=2)}

**TOP FINDINGS:**
"""
        
        for i, finding in enumerate(top_findings, 1):
            summary_prompt += f"""
{i}. {finding.type} - {finding.severity}
   Path: {finding.path}
   Summary: {finding.short_summary}
   Confidence: {finding.confidence}
"""
        
        summary_prompt += """

**TASK:**
Provide a professional security assessment summary in JSON format:
{
    "executive_summary": "2-3 sentence executive summary",
    "risk_assessment": "Overall risk level: Critical|High|Medium|Low",
    "key_findings": ["Key finding 1", "Key finding 2", "Key finding 3"],
    "immediate_actions": ["Action 1", "Action 2", "Action 3"],
    "recommendations": ["Recommendation 1", "Recommendation 2", "Recommendation 3"],
    "next_steps": ["Next step 1", "Next step 2"]
}

Focus on:
- Business impact
- Immediate risks
- Prioritized remediation
- Long-term security improvements

Respond with ONLY the JSON object.
"""
        
        try:
            response = await self.llm_client.chat(summary_prompt)
            
            # Parse JSON response
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                
                if json_start != -1 and json_end != -1:
                    json_str = response[json_start:json_end]
                    summary = json.loads(json_str)
                    
                    # Add metadata
                    summary['metadata'] = {
                        'target_url': target_url,
                        'scan_profile': scan_profile,
                        'total_findings': len(enriched_findings),
                        'severity_breakdown': severity_counts,
                        'scan_timestamp': self._get_current_timestamp()
                    }
                    
                    return summary
                else:
                    raise ValueError("No JSON found in response")
                    
            except (json.JSONDecodeError, ValueError) as e:
                print(f"Error parsing summary JSON: {e}")
                return self._create_fallback_summary(enriched_findings, target_url, scan_profile)
                
        except Exception as e:
            print(f"Error generating summary: {e}")
            return self._create_fallback_summary(enriched_findings, target_url, scan_profile)
    
    def _create_fallback_summary(self, enriched_findings: List[EnrichedFinding], target_url: str, scan_profile: str) -> Dict[str, Any]:
        """Create fallback summary when LLM fails"""
        severity_counts = {}
        for finding in enriched_findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall risk
        if severity_counts.get('Critical', 0) > 0:
            risk_level = 'Critical'
        elif severity_counts.get('High', 0) > 0:
            risk_level = 'High'
        elif severity_counts.get('Medium', 0) > 0:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            "executive_summary": f"Security scan of {target_url} identified {len(enriched_findings)} vulnerabilities with {risk_level} overall risk level.",
            "risk_assessment": risk_level,
            "key_findings": [f"{f.type} at {f.path}" for f in enriched_findings[:3]],
            "immediate_actions": [
                "Review and prioritize findings by severity",
                "Implement immediate fixes for critical vulnerabilities",
                "Schedule security team review"
            ],
            "recommendations": [
                "Implement regular security scanning",
                "Establish vulnerability management process",
                "Conduct security training for development team"
            ],
            "next_steps": [
                "Remediate critical and high severity findings",
                "Implement security controls",
                "Schedule follow-up security assessment"
            ],
            "metadata": {
                'target_url': target_url,
                'scan_profile': scan_profile,
                'total_findings': len(enriched_findings),
                'severity_breakdown': severity_counts,
                'scan_timestamp': self._get_current_timestamp()
            }
        }
    
    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numeric score for sorting"""
        scores = {
            'Critical': 5,
            'High': 4,
            'Medium': 3,
            'Low': 2,
            'Info': 1
        }
        return scores.get(severity, 0)
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

