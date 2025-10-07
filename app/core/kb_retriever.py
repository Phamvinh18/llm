import os, json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import hashlib

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
KB_FILE = os.path.join(DATA_DIR, 'payloads_expanded.json')
RAG_DATASET_FILE = os.path.join(DATA_DIR, 'rag_dataset.json')

@dataclass
class KnowledgeDocument:
    """Knowledge document structure"""
    id: str
    title: str
    content: str
    category: str
    tags: List[str]
    relevance_score: float = 0.0
    source: str = "payloads_expanded.json"

class AdvancedKBRetriever:
    """Advanced Knowledge Base Retriever with RAG capabilities"""
    
    def __init__(self):
        self.docs = []
        self.vulnerability_kb = {}
        self.security_patterns = {}
        self._load_knowledge_base()
        self._initialize_security_patterns()
    
    def _load_knowledge_base(self):
        """Load and process knowledge base"""
        # Load original payloads
        if os.path.exists(KB_FILE):
            try:
                pdata = json.load(open(KB_FILE, 'r', encoding='utf-8'))
                for k, v in pdata.items():
                    # Create comprehensive knowledge document
                    content = self._create_comprehensive_content(k, v)
                    
                    doc = KnowledgeDocument(
                        id=f'payload-{k}',
                        title=f"{k.replace('_', ' ').title()} Payloads",
                        content=content,
                        category=self._categorize_vulnerability(k),
                        tags=self._extract_tags(k, v),
                        source="payloads_expanded.json"
                    )
                    
                    self.docs.append(doc)
                    self.vulnerability_kb[k] = doc
                    
            except Exception as e:
                print(f"Error loading knowledge base: {e}")
        
        # Load RAG dataset
        if os.path.exists(RAG_DATASET_FILE):
            try:
                rag_data = json.load(open(RAG_DATASET_FILE, 'r', encoding='utf-8'))
                self._load_rag_dataset(rag_data)
            except Exception as e:
                print(f"Error loading RAG dataset: {e}")
        
        # Load LLM vulnerability RAG dataset
        llm_rag_file = os.path.join(DATA_DIR, 'llm_vulnerability_rag.json')
        if os.path.exists(llm_rag_file):
            try:
                llm_rag_data = json.load(open(llm_rag_file, 'r', encoding='utf-8'))
                self._load_llm_vulnerability_rag(llm_rag_data)
            except Exception as e:
                print(f"Error loading LLM vulnerability RAG: {e}")
    
    def _load_rag_dataset(self, rag_data: Dict[str, Any]):
        """Load RAG dataset into knowledge base"""
        # Load vulnerability knowledge
        vuln_knowledge = rag_data.get('vulnerability_knowledge', {})
        for vuln_type, vuln_info in vuln_knowledge.items():
            content = self._create_rag_content(vuln_type, vuln_info)
            
            doc = KnowledgeDocument(
                id=f'rag-{vuln_type}',
                title=vuln_info.get('title', f"{vuln_type.replace('_', ' ').title()}"),
                content=content,
                category=self._categorize_vulnerability(vuln_type),
                tags=self._extract_rag_tags(vuln_type, vuln_info),
                source="rag_dataset.json"
            )
            
            self.docs.append(doc)
            self.vulnerability_kb[vuln_type] = doc
        
        # Load scanning techniques
        scan_techniques = rag_data.get('scanning_techniques', {})
        for technique_type, technique_info in scan_techniques.items():
            content = self._create_technique_content(technique_type, technique_info)
            
            doc = KnowledgeDocument(
                id=f'technique-{technique_type}',
                title=f"{technique_type.replace('_', ' ').title()} Techniques",
                content=content,
                category="Scanning Techniques",
                tags=[technique_type, "scanning", "techniques"],
                source="rag_dataset.json"
            )
            
            self.docs.append(doc)
        
        # Load payload generation info
        payload_info = rag_data.get('payload_generation', {})
        for payload_type, payloads in payload_info.items():
            content = self._create_payload_content(payload_type, payloads)
            
            doc = KnowledgeDocument(
                id=f'payload-gen-{payload_type}',
                title=f"{payload_type.replace('_', ' ').title()} Generation",
                content=content,
                category="Payload Generation",
                tags=[payload_type, "payload", "generation"],
                source="rag_dataset.json"
            )
            
            self.docs.append(doc)
    
    def _create_rag_content(self, vuln_type: str, vuln_info: Dict[str, Any]) -> str:
        """Create content from RAG dataset vulnerability info"""
        content_parts = []
        
        # Add basic info
        content_parts.append(f"Title: {vuln_info.get('title', '')}")
        content_parts.append(f"Description: {vuln_info.get('description', '')}")
        
        # Add types
        if 'types' in vuln_info:
            content_parts.append(f"Types: {', '.join(vuln_info['types'])}")
        
        # Add detection patterns
        if 'detection_patterns' in vuln_info:
            content_parts.append("Detection Patterns:")
            for pattern in vuln_info['detection_patterns'][:10]:  # Limit to first 10
                content_parts.append(f"- {pattern}")
        
        # Add impact
        if 'impact' in vuln_info:
            content_parts.append(f"Impact: {vuln_info['impact']}")
        
        # Add remediation
        if 'remediation' in vuln_info:
            content_parts.append("Remediation:")
            for rem in vuln_info['remediation']:
                content_parts.append(f"- {rem}")
        
        # Add testing methods
        if 'testing_methods' in vuln_info:
            content_parts.append("Testing Methods:")
            for method in vuln_info['testing_methods']:
                content_parts.append(f"- {method}")
        
        return '\n'.join(content_parts)
    
    def _create_technique_content(self, technique_type: str, technique_info: Dict[str, Any]) -> str:
        """Create content from scanning techniques"""
        content_parts = []
        
        content_parts.append(f"Technique Type: {technique_type.replace('_', ' ').title()}")
        
        for key, value in technique_info.items():
            if isinstance(value, list):
                content_parts.append(f"{key.replace('_', ' ').title()}:")
                for item in value:
                    content_parts.append(f"- {item}")
            else:
                content_parts.append(f"{key.replace('_', ' ').title()}: {value}")
        
        return '\n'.join(content_parts)
    
    def _create_payload_content(self, payload_type: str, payloads: Dict[str, Any]) -> str:
        """Create content from payload generation info"""
        content_parts = []
        
        content_parts.append(f"Payload Type: {payload_type.replace('_', ' ').title()}")
        
        for category, payload_list in payloads.items():
            if isinstance(payload_list, list):
                content_parts.append(f"{category.replace('_', ' ').title()}:")
                for payload in payload_list[:5]:  # Limit to first 5
                    content_parts.append(f"- {payload}")
        
        return '\n'.join(content_parts)
    
    def _extract_rag_tags(self, vuln_type: str, vuln_info: Dict[str, Any]) -> List[str]:
        """Extract tags from RAG dataset"""
        tags = [vuln_type, self._categorize_vulnerability(vuln_type)]
        
        # Add tags based on content
        content = str(vuln_info).lower()
        if 'javascript' in content or 'script' in content:
            tags.append('javascript')
        if 'sql' in content or 'database' in content:
            tags.append('database')
        if 'file' in content or 'path' in content:
            tags.append('file-system')
        if 'command' in content or 'exec' in content:
            tags.append('command-execution')
        if 'request' in content or 'http' in content:
            tags.append('http-request')
        
        # Add severity tag
        if 'severity' in vuln_info:
            tags.append(f"severity-{vuln_info['severity'].lower()}")
        
        return list(set(tags))
    
    def _load_llm_vulnerability_rag(self, llm_rag_data: Dict[str, Any]):
        """Load LLM vulnerability RAG data into knowledge base"""
        # Load vulnerability detection knowledge
        vuln_detection = llm_rag_data.get('llm_vulnerability_detection', {})
        for vuln_type, vuln_info in vuln_detection.items():
            content = self._create_llm_vuln_content(vuln_type, vuln_info)
            
            doc = KnowledgeDocument(
                id=f'llm-{vuln_type}',
                title=f"LLM Detection: {vuln_info.get('title', vuln_type.replace('_', ' ').title())}",
                content=content,
                category="LLM Vulnerability Detection",
                tags=self._extract_llm_vuln_tags(vuln_type, vuln_info),
                source="llm_vulnerability_rag.json"
            )
            
            self.docs.append(doc)
            self.vulnerability_kb[f'llm_{vuln_type}'] = doc
        
        # Load analysis framework
        analysis_framework = llm_rag_data.get('llm_analysis_framework', {})
        if analysis_framework:
            content = self._create_analysis_framework_content(analysis_framework)
            
            doc = KnowledgeDocument(
                id='llm-analysis-framework',
                title="LLM Analysis Framework",
                content=content,
                category="LLM Analysis Framework",
                tags=["llm", "analysis", "framework", "detection"],
                source="llm_vulnerability_rag.json"
            )
            
            self.docs.append(doc)
    
    def _create_llm_vuln_content(self, vuln_type: str, vuln_info: Dict[str, Any]) -> str:
        """Create content from LLM vulnerability info"""
        content_parts = []
        
        # Add basic info
        content_parts.append(f"Title: {vuln_info.get('title', '')}")
        content_parts.append(f"Description: {vuln_info.get('description', '')}")
        
        # Add LLM detection methods
        if 'llm_detection_methods' in vuln_info:
            content_parts.append("LLM Detection Methods:")
            for method in vuln_info['llm_detection_methods']:
                content_parts.append(f"- {method}")
        
        # Add LLM analysis capabilities
        if 'llm_analysis_capabilities' in vuln_info:
            content_parts.append("LLM Analysis Capabilities:")
            for capability in vuln_info['llm_analysis_capabilities']:
                content_parts.append(f"- {capability}")
        
        # Add detection patterns
        if 'detection_patterns' in vuln_info:
            content_parts.append("Detection Patterns:")
            for pattern in vuln_info['detection_patterns'][:10]:  # Limit to first 10
                content_parts.append(f"- {pattern}")
        
        # Add response indicators
        if 'response_indicators' in vuln_info:
            content_parts.append("Response Indicators:")
            for indicator in vuln_info['response_indicators']:
                content_parts.append(f"- {indicator}")
        
        # Add LLM analysis prompts
        if 'llm_analysis_prompts' in vuln_info:
            content_parts.append("LLM Analysis Prompts:")
            for prompt in vuln_info['llm_analysis_prompts']:
                content_parts.append(f"- {prompt}")
        
        # Add severity levels
        if 'severity_levels' in vuln_info:
            content_parts.append("Severity Levels:")
            for level, description in vuln_info['severity_levels'].items():
                content_parts.append(f"- {level}: {description}")
        
        return '\n'.join(content_parts)
    
    def _create_analysis_framework_content(self, framework: Dict[str, Any]) -> str:
        """Create content from analysis framework"""
        content_parts = []
        
        # Add detection phases
        if 'detection_phases' in framework:
            content_parts.append("Detection Phases:")
            for phase in framework['detection_phases']:
                content_parts.append(f"- {phase.get('phase', '')}: {phase.get('description', '')}")
                if 'llm_tasks' in phase:
                    for task in phase['llm_tasks']:
                        content_parts.append(f"  * {task}")
        
        # Add LLM capabilities
        if 'llm_capabilities' in framework:
            content_parts.append("LLM Capabilities:")
            for capability in framework['llm_capabilities']:
                content_parts.append(f"- {capability}")
        
        # Add analysis metrics
        if 'analysis_metrics' in framework:
            content_parts.append("Analysis Metrics:")
            for metric in framework['analysis_metrics']:
                content_parts.append(f"- {metric}")
        
        return '\n'.join(content_parts)
    
    def _extract_llm_vuln_tags(self, vuln_type: str, vuln_info: Dict[str, Any]) -> List[str]:
        """Extract tags from LLM vulnerability info"""
        tags = [vuln_type, "llm-detection", "vulnerability-analysis"]
        
        # Add tags based on content
        content = str(vuln_info).lower()
        if 'sql' in content:
            tags.append('sql-injection')
        if 'xss' in content:
            tags.append('xss')
        if 'idor' in content:
            tags.append('idor')
        if 'csrf' in content:
            tags.append('csrf')
        if 'ssrf' in content:
            tags.append('ssrf')
        if 'misconfiguration' in content:
            tags.append('misconfiguration')
        
        # Add severity tags
        if 'severity_levels' in vuln_info:
            for level in vuln_info['severity_levels'].keys():
                tags.append(f"severity-{level}")
        
        return list(set(tags))
    
    def _create_comprehensive_content(self, vuln_type: str, vuln_data: Dict) -> str:
        """Create comprehensive content for knowledge document"""
        content_parts = []
        
        # Add description/notes
        if 'notes' in vuln_data:
            content_parts.append(f"Description: {vuln_data['notes']}")
        
        # Add payloads
        if 'payloads' in vuln_data:
            content_parts.append("Payloads:")
            for payload in vuln_data['payloads']:
                content_parts.append(f"- {payload}")
        
        # Add vulnerability-specific information
        vuln_info = self._get_vulnerability_info(vuln_type)
        if vuln_info:
            content_parts.append(f"Vulnerability Info: {vuln_info}")
        
        # Add detection patterns
        detection_patterns = self._get_detection_patterns(vuln_type)
        if detection_patterns:
            content_parts.append(f"Detection Patterns: {detection_patterns}")
        
        # Add mitigation strategies
        mitigation = self._get_mitigation_strategies(vuln_type)
        if mitigation:
            content_parts.append(f"Mitigation: {mitigation}")
        
        return '\n'.join(content_parts)
    
    def _categorize_vulnerability(self, vuln_type: str) -> str:
        """Categorize vulnerability type"""
        categories = {
            'xss': 'Client-Side',
            'sql_injection': 'Server-Side',
            'path_traversal': 'Server-Side',
            'command_injection': 'Server-Side',
            'ssrf': 'Server-Side',
            'csrf': 'Client-Side',
            'xxe': 'Server-Side',
            'ldap_injection': 'Server-Side',
            'xml_injection': 'Server-Side',
            'nosql_injection': 'Server-Side'
        }
        return categories.get(vuln_type, 'Unknown')
    
    def _extract_tags(self, vuln_type: str, vuln_data: Dict) -> List[str]:
        """Extract relevant tags"""
        tags = [vuln_type, self._categorize_vulnerability(vuln_type)]
        
        # Add tags based on content
        content = str(vuln_data).lower()
        if 'javascript' in content or 'script' in content:
            tags.append('javascript')
        if 'sql' in content or 'database' in content:
            tags.append('database')
        if 'file' in content or 'path' in content:
            tags.append('file-system')
        if 'command' in content or 'exec' in content:
            tags.append('command-execution')
        
        return list(set(tags))
    
    def _get_vulnerability_info(self, vuln_type: str) -> str:
        """Get detailed vulnerability information"""
        vuln_info = {
            'xss': 'Cross-Site Scripting allows attackers to inject malicious scripts into web pages',
            'sql_injection': 'SQL Injection allows attackers to manipulate database queries',
            'path_traversal': 'Path Traversal allows attackers to access files outside web root',
            'command_injection': 'Command Injection allows attackers to execute system commands',
            'ssrf': 'Server-Side Request Forgery allows attackers to make requests from server',
            'csrf': 'Cross-Site Request Forgery allows attackers to perform actions on behalf of users',
            'xxe': 'XML External Entity allows attackers to access local files or perform SSRF',
            'ldap_injection': 'LDAP Injection allows attackers to manipulate LDAP queries',
            'xml_injection': 'XML Injection allows attackers to manipulate XML processing',
            'nosql_injection': 'NoSQL Injection allows attackers to manipulate NoSQL queries'
        }
        return vuln_info.get(vuln_type, 'Unknown vulnerability type')
    
    def _get_detection_patterns(self, vuln_type: str) -> str:
        """Get detection patterns for vulnerability"""
        patterns = {
            'xss': 'Look for script tags, javascript:, on* events, alert(), document.cookie',
            'sql_injection': 'Look for SQL errors, UNION SELECT, OR 1=1, database error messages',
            'path_traversal': 'Look for ../, ..\\, /etc/passwd, C:\\windows\\system32',
            'command_injection': 'Look for command separators ; | &, system command output',
            'ssrf': 'Look for internal IPs, localhost, 127.0.0.1, cloud metadata endpoints',
            'csrf': 'Look for missing CSRF tokens, same-origin policy violations',
            'xxe': 'Look for XML processing, external entity references, file access',
            'ldap_injection': 'Look for LDAP error messages, filter manipulation',
            'xml_injection': 'Look for XML parsing errors, entity expansion',
            'nosql_injection': 'Look for NoSQL error messages, query manipulation'
        }
        return patterns.get(vuln_type, 'No specific patterns available')
    
    def _get_mitigation_strategies(self, vuln_type: str) -> str:
        """Get mitigation strategies for vulnerability"""
        mitigations = {
            'xss': 'Use output encoding, Content Security Policy, input validation',
            'sql_injection': 'Use parameterized queries, input validation, least privilege',
            'path_traversal': 'Validate file paths, use whitelist, chroot jail',
            'command_injection': 'Avoid system commands, use safe APIs, input validation',
            'ssrf': 'Validate URLs, use allowlist, network segmentation',
            'csrf': 'Use CSRF tokens, same-origin policy, double submit cookies',
            'xxe': 'Disable external entities, use safe XML parsers, input validation',
            'ldap_injection': 'Use parameterized queries, input validation, escape special characters',
            'xml_injection': 'Use safe XML parsers, input validation, disable external entities',
            'nosql_injection': 'Use parameterized queries, input validation, type checking'
        }
        return mitigations.get(vuln_type, 'General security best practices')
    
    def _initialize_security_patterns(self):
        """Initialize security patterns for enhanced matching"""
        self.security_patterns = {
            'error_patterns': [
                r'error|exception|warning|fatal|critical',
                r'sql.*error|database.*error|mysql.*error',
                r'php.*error|python.*error|java.*error',
                r'stack.*trace|debug.*info|traceback'
            ],
            'vulnerability_indicators': [
                r'<script|javascript:|on\w+\s*=',
                r'union.*select|or.*1.*=.*1|drop.*table',
                r'\.\./|\.\.\\|/etc/passwd|C:\\windows',
                r';\s*(ls|dir|whoami|id)|\|\s*(ls|dir|whoami|id)',
                r'127\.0\.0\.1|localhost|169\.254\.169\.254'
            ],
            'security_headers': [
                r'x-frame-options|x-content-type-options|x-xss-protection',
                r'content-security-policy|strict-transport-security',
                r'referrer-policy|permissions-policy'
            ]
        }
    
    def retrieve(self, query: str, k: int = 5, context: Optional[Dict] = None) -> List[KnowledgeDocument]:
        """Advanced retrieval with context awareness"""
        query_lower = query.lower()
        
        # Enhanced scoring with multiple factors
        scored_docs = []
        
        for doc in self.docs:
            score = self._calculate_relevance_score(query_lower, doc, context)
            if score > 0:
                doc.relevance_score = score
                scored_docs.append(doc)
        
        # Sort by relevance score
        scored_docs.sort(key=lambda x: x.relevance_score, reverse=True)
        
        return scored_docs[:k]
    
    def _calculate_relevance_score(self, query: str, doc: KnowledgeDocument, context: Optional[Dict] = None) -> float:
        """Calculate relevance score with multiple factors"""
        score = 0.0
        
        # 1. Direct text matching
        content_lower = doc.content.lower()
        query_tokens = query.split()
        
        # Exact phrase matching (higher weight)
        if query in content_lower:
            score += 10.0
        
        # Token matching
        for token in query_tokens:
            if token in content_lower:
                score += 1.0
        
        # 2. Category matching
        if context and 'vulnerability_type' in context:
            if context['vulnerability_type'] in doc.tags:
                score += 5.0
        
        # 3. Tag matching
        for tag in doc.tags:
            if tag in query_lower:
                score += 2.0
        
        # 4. Title matching (higher weight)
        if any(token in doc.title.lower() for token in query_tokens):
            score += 3.0
        
        # 5. Security pattern matching
        for pattern_type, patterns in self.security_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    if any(re.search(pattern, tag) for tag in doc.tags):
                        score += 2.0
        
        # 6. Context-aware scoring
        if context:
            # Boost score for relevant vulnerability types
            if 'vulnerability_type' in context:
                vuln_type = context['vulnerability_type']
                if vuln_type in doc.id or vuln_type in doc.tags:
                    score += 4.0
            
            # Boost score for relevant categories
            if 'category' in context:
                if context['category'] == doc.category:
                    score += 2.0
        
        return score
    
    def get_vulnerability_specific_knowledge(self, vuln_type: str) -> Optional[KnowledgeDocument]:
        """Get knowledge specific to vulnerability type"""
        return self.vulnerability_kb.get(vuln_type)
    
    def search_by_category(self, category: str) -> List[KnowledgeDocument]:
        """Search documents by category"""
        return [doc for doc in self.docs if doc.category == category]
    
    def get_related_vulnerabilities(self, vuln_type: str) -> List[KnowledgeDocument]:
        """Get related vulnerabilities"""
        related = []
        target_doc = self.vulnerability_kb.get(vuln_type)
        
        if target_doc:
            for doc in self.docs:
                if doc.id != target_doc.id and doc.category == target_doc.category:
                    related.append(doc)
        
        return related[:3]  # Return top 3 related
    
    def get_knowledge_summary(self) -> Dict[str, Any]:
        """Get summary of knowledge base"""
        categories = {}
        for doc in self.docs:
            if doc.category not in categories:
                categories[doc.category] = 0
            categories[doc.category] += 1
        
        return {
            'total_documents': len(self.docs),
            'categories': categories,
            'vulnerability_types': list(self.vulnerability_kb.keys()),
            'tags': list(set(tag for doc in self.docs for tag in doc.tags))
        }

# Backward compatibility
class KBRetriever(AdvancedKBRetriever):
    """Backward compatible KBRetriever"""
    
    def retrieve(self, query, k=3):
        """Backward compatible retrieve method"""
        results = super().retrieve(query, k)
        # Convert to old format
        return [{'id': doc.id, 'text': doc.content} for doc in results]
