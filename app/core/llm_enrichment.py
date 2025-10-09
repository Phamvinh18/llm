"""
LLM Enrichment System - Enrich findings với LLM và track provenance
"""

import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import re

@dataclass
class RAGDocument:
    content: str
    source: str
    doc_id: str
    title: str
    url: Optional[str] = None

@dataclass
class EnrichmentResult:
    finding_id: str
    severity: str
    confidence: str
    cvss_v3: Optional[str]
    exploitability_score: int
    justification: str
    safe_poc_steps: List[str]
    remediation: List[Dict[str, str]]
    references: List[Dict[str, str]]
    provenance: List[Dict[str, str]]
    llm_analysis: str

class LLMEnrichment:
    """LLM enrichment system với provenance tracking"""
    
    def __init__(self, llm_client, rag_retriever):
        self.llm_client = llm_client
        self.rag_retriever = rag_retriever
    
    async def enrich_finding(self, finding: Dict[str, Any]) -> EnrichmentResult:
        """Enrich finding với LLM analysis và RAG context"""
        try:
            # Get RAG context
            rag_docs = await self._get_rag_context(finding)
            
            # Build enrichment prompt
            prompt = self._build_enrichment_prompt(finding, rag_docs)
            
            # Call LLM
            llm_response = self.llm_client.chat(prompt)
            
            # Parse and validate response
            enrichment_result = self._parse_llm_response(llm_response, finding, rag_docs)
            
            # Validate provenance
            self._validate_provenance(enrichment_result, rag_docs)
            
            return enrichment_result
            
        except Exception as e:
            print(f"LLM enrichment error: {e}")
            return self._create_fallback_result(finding, str(e))
    
    async def _get_rag_context(self, finding: Dict[str, Any]) -> List[RAGDocument]:
        """Get RAG context for finding"""
        try:
            vuln_type = finding.get('type', '').lower()
            path = finding.get('path', '')
            param = finding.get('param', '')
            evidence = finding.get('evidence_snippet', '')
            
            # Build query
            query_parts = [vuln_type, "vulnerability", "detection", "remediation"]
            if path:
                query_parts.append("path")
            if param:
                query_parts.append("parameter")
            if evidence:
                query_parts.append("evidence")
            
            query = " ".join(query_parts)
            
            # Retrieve documents
            docs = self.rag_retriever.retrieve(query, k=5)
            
            # Convert to RAGDocument objects
            rag_docs = []
            for i, doc in enumerate(docs):
                content = getattr(doc, 'content', str(doc)) if hasattr(doc, 'content') else str(doc)
                source = getattr(doc, 'source', 'Unknown')
                
                rag_doc = RAGDocument(
                    content=content,
                    source=source,
                    doc_id=f"doc_{source}_{i}",
                    title=f"{source} - {vuln_type.title()}",
                    url=None
                )
                rag_docs.append(rag_doc)
            
            return rag_docs
                
            except Exception as e:
            print(f"RAG context error: {e}")
            return []
    
    def _build_enrichment_prompt(self, finding: Dict[str, Any], rag_docs: List[RAGDocument]) -> str:
        """Build LLM enrichment prompt"""
        
        # Format RAG documents
        rag_context = ""
        for doc in rag_docs:
            rag_context += f"Source: {doc.source} (ID: {doc.doc_id})\n"
            rag_context += f"Content: {doc.content[:500]}...\n"
            rag_context += "---\n"
        
        prompt = f"""
You are a senior web security engineer. Analyze this finding and provide enrichment.

FINDING_JSON: {json.dumps(finding, indent=2)}

EVIDENCE_SNIPPET: {finding.get('evidence_snippet', '')}

RAG_CONTEXT:
{rag_context}

Task: Produce JSON with keys:
- id, short_summary, severity (Low/Med/High/Critical), confidence (Low/Med/High), 
- cvss_v3, exploitability_score (0-100), justification, safe_poc_steps, 
- remediation, references, provenance

Rules:
1) Use ONLY the provided evidence and RAG context to justify severity and confidence.
2) Do NOT invent facts. If insufficient evidence, set confidence to Low.
3) Output strictly valid JSON.
4) Include source references from RAG context in provenance field.
5) For remediation, provide specific code/config examples.
6) For safe_poc_steps, provide non-destructive commands only.

Expected JSON format:
{{
    "id": "{finding.get('id', '')}",
    "short_summary": "Brief description of the finding",
    "severity": "High",
    "confidence": "High", 
    "cvss_v3": "6.1",
    "exploitability_score": 85,
    "justification": "Detailed justification citing evidence and RAG sources",
    "safe_poc_steps": [
        "curl -s 'http://target.com/page?param=<script>alert(1)</script>' -o - | grep -i script"
    ],
    "remediation": [
        {{
            "type": "php",
            "description": "Output encoding",
            "code": "echo htmlspecialchars($_GET['param'], ENT_QUOTES, 'UTF-8');"
        }}
    ],
    "references": [
        {{
            "title": "OWASP XSS Prevention Cheat Sheet",
            "source": "OWASP",
            "url": "https://owasp.org/www-community/xss"
        }}
    ],
    "provenance": [
        {{
            "claim": "remediation",
            "source_doc_id": "doc_owasp_0",
            "snippet": "Use contextual output encoding..."
        }}
    ]
}}
"""
        return prompt
    
    def _parse_llm_response(self, llm_response: str, finding: Dict[str, Any], 
                          rag_docs: List[RAGDocument]) -> EnrichmentResult:
        """Parse LLM response and create enrichment result"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                data = json.loads(json_str)
            else:
                # Fallback parsing
                data = self._parse_fallback_response(llm_response)
            
            # Create enrichment result
            result = EnrichmentResult(
                finding_id=finding.get('id', ''),
                severity=data.get('severity', 'Unknown'),
                confidence=data.get('confidence', 'Low'),
                cvss_v3=data.get('cvss_v3'),
                exploitability_score=data.get('exploitability_score', 0),
                justification=data.get('justification', ''),
                safe_poc_steps=data.get('safe_poc_steps', []),
                remediation=data.get('remediation', []),
                references=data.get('references', []),
                provenance=data.get('provenance', []),
                llm_analysis=llm_response
            )
            
            return result
                
        except Exception as e:
            print(f"Error parsing LLM response: {e}")
            return self._create_fallback_result(finding, f"Parse error: {str(e)}")
    
    def _parse_fallback_response(self, response: str) -> Dict[str, Any]:
        """Fallback parsing if JSON extraction fails"""
        data = {
            "severity": "Unknown",
            "confidence": "Low",
            "cvss_v3": None,
            "exploitability_score": 0,
            "justification": response[:500],
            "safe_poc_steps": [],
            "remediation": [],
            "references": [],
            "provenance": []
        }
        
        # Try to extract severity
        if "critical" in response.lower():
            data["severity"] = "Critical"
        elif "high" in response.lower():
            data["severity"] = "High"
        elif "medium" in response.lower():
            data["severity"] = "Medium"
        elif "low" in response.lower():
            data["severity"] = "Low"
        
        return data
    
    def _validate_provenance(self, result: EnrichmentResult, rag_docs: List[RAGDocument]):
        """Validate that provenance claims are supported by RAG documents"""
        try:
            # Check if justification contains evidence or RAG content
            justification = result.justification.lower()
            evidence_found = False
            rag_found = False
            
            # Check for evidence snippets
            if any(keyword in justification for keyword in ['script', 'alert', 'payload', 'injection']):
                evidence_found = True
            
            # Check for RAG content
            for doc in rag_docs:
                if any(word in justification for word in doc.content.lower().split()[:10]):
                    rag_found = True
                    break
            
            # Adjust confidence if no evidence/RAG support
            if not evidence_found and not rag_found:
                result.confidence = "Low"
                result.justification += " [Note: Limited evidence support - manual review recommended]"
            
        except Exception as e:
            print(f"Provenance validation error: {e}")
    
    def _create_fallback_result(self, finding: Dict[str, Any], error_msg: str) -> EnrichmentResult:
        """Create fallback result when enrichment fails"""
        return EnrichmentResult(
            finding_id=finding.get('id', ''),
            severity="Unknown",
            confidence="Low",
            cvss_v3=None,
            exploitability_score=0,
            justification=f"Enrichment failed: {error_msg}",
            safe_poc_steps=[],
            remediation=[],
            references=[],
            provenance=[],
            llm_analysis=error_msg
        )
    
    def merge_enrichment_with_finding(self, finding: Dict[str, Any], 
                                    enrichment: EnrichmentResult) -> Dict[str, Any]:
        """Merge enrichment result back into finding"""
        try:
            # Update finding with enrichment data
            finding.update({
                "severity": enrichment.severity,
                "confidence": enrichment.confidence,
                "cvss_v3": enrichment.cvss_v3,
                "exploitability_score": enrichment.exploitability_score,
                "justification": enrichment.justification,
                "safe_poc_steps": enrichment.safe_poc_steps,
                "remediation": enrichment.remediation,
                "references": enrichment.references,
                "provenance": enrichment.provenance,
                "llm_analysis": enrichment.llm_analysis,
                "enriched_at": time.strftime('%Y-%m-%dT%H:%M:%SZ')
            })
            
            return finding
            
        except Exception as e:
            print(f"Error merging enrichment: {e}")
            return finding
    
    def calculate_exploitability_score(self, finding: Dict[str, Any]) -> int:
        """Calculate exploitability score based on evidence"""
        try:
            score = 0
            evidence = finding.get('evidence_snippet', '').lower()
            vuln_type = finding.get('type', '').lower()
            
            # Base score by vulnerability type
            if 'xss' in vuln_type:
                score += 30
            elif 'sql' in vuln_type:
                score += 40
            elif 'rce' in vuln_type:
                score += 50
            else:
                score += 20
            
            # Evidence reflection
            if any(marker in evidence for marker in ['<script>', 'alert(', 'javascript:']):
                score += 30
            
            # Parameter location
            if finding.get('param'):
                score += 20
            
            # Confirmatory tests
            confirm_tests = finding.get('confirmatory_tests', [])
            if any(test.get('result') == 'passed' for test in confirm_tests):
                score += 20
            
            # Security headers (reduce score if present)
            # This would need to be checked against actual response headers
            
            return min(100, max(0, score))
                
        except Exception as e:
            print(f"Error calculating exploitability score: {e}")
            return 0
    
    def generate_safe_poc(self, finding: Dict[str, Any]) -> List[str]:
        """Generate safe PoC steps"""
        try:
            poc_steps = []
            vuln_type = finding.get('type', '').lower()
            path = finding.get('path', '')
            param = finding.get('param', '')
            target = finding.get('target', '')
            
            if 'xss' in vuln_type and param:
                # Safe XSS PoC
                poc_steps.append(f"curl -s '{target}{path}?{param}=<script>alert(1)</script>' -o - | grep -i script")
                poc_steps.append(f"# Check if payload is reflected in response")
                poc_steps.append(f"# Non-destructive test - no JavaScript execution")
            
            elif 'sql' in vuln_type and param:
                # Safe SQL injection PoC
                poc_steps.append(f"curl -s '{target}{path}?{param}=1' -o response1.txt")
                poc_steps.append(f"curl -s '{target}{path}?{param}=1\\'' -o response2.txt")
                poc_steps.append(f"diff response1.txt response2.txt")
                poc_steps.append(f"# Look for SQL error messages or different responses")
            
            elif 'lfi' in vuln_type and param:
                # Safe LFI PoC
                poc_steps.append(f"curl -s '{target}{path}?{param}=../../../etc/passwd' -o - | head -5")
                poc_steps.append(f"# Check for file content disclosure")
            
        else:
                poc_steps.append(f"# Manual verification required for {vuln_type}")
                poc_steps.append(f"# Target: {target}{path}")
                if param:
                    poc_steps.append(f"# Parameter: {param}")
            
            return poc_steps
            
        except Exception as e:
            print(f"Error generating PoC: {e}")
            return ["# Error generating PoC steps"]
    
    def generate_remediation(self, finding: Dict[str, Any], rag_docs: List[RAGDocument]) -> List[Dict[str, str]]:
        """Generate remediation suggestions based on RAG context"""
        try:
            remediation = []
            vuln_type = finding.get('type', '').lower()
            
            # Base remediation by vulnerability type
            if 'xss' in vuln_type:
                remediation.append({
                    "type": "php",
                    "description": "Output encoding",
                    "code": "echo htmlspecialchars($_GET['param'], ENT_QUOTES, 'UTF-8');"
                })
                remediation.append({
                    "type": "http",
                    "description": "Content Security Policy",
                    "code": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;"
                })
            
            elif 'sql' in vuln_type:
                remediation.append({
                    "type": "php",
                    "description": "Prepared statements",
                    "code": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);"
                })
            
            elif 'lfi' in vuln_type:
                remediation.append({
                    "type": "php",
                    "description": "Path validation",
                    "code": "$allowed_paths = ['/var/www/', '/uploads/']; if (!in_array(dirname($file), $allowed_paths)) { die('Access denied'); }"
                })
            
            # Add RAG-based remediation if available
            for doc in rag_docs:
                if 'remediation' in doc.content.lower() or 'fix' in doc.content.lower():
                    remediation.append({
                        "type": "rag",
                        "description": f"From {doc.source}",
                        "code": doc.content[:200] + "..."
                    })
                    break
            
            return remediation
            
        except Exception as e:
            print(f"Error generating remediation: {e}")
            return [{"type": "error", "description": "Error generating remediation", "code": str(e)}]