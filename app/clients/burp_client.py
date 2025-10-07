import json, time, os
import requests
from typing import Dict, List, Any
from app.core.burp_analyzer import BurpFindingAnalyzer

class BurpClient:
    def __init__(self, base_url=None, api_key=None):
        self.base_url = base_url or 'mock'
        self.api_key = api_key or 'Z0ID48POpyXiYhKAksgHG4UlWB0bCHAL'
        self.scan_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'scans')
        self.enhanced_analyzer = BurpFindingAnalyzer()
        os.makedirs(self.scan_dir, exist_ok=True)
    
    def start_scan(self, target_url):
        sid = f'burp-scan-{int(time.time())}'
        
        # Generate comprehensive mock findings
        issues = self.enhanced_analyzer.generate_comprehensive_findings(target_url)
        issues = self.enhanced_analyzer.analyze_suspicious_errors(issues)
        
        scan_data = {
            'scan_id': sid,
            'target': target_url,
            'started_at': time.time(),
            'status': 'completed',
            'issues': issues,
            'summary': {
                'total_findings': len(issues),
                'critical_count': len([i for i in issues if i.get('severity') == 'Critical']),
                'high_count': len([i for i in issues if i.get('severity') == 'High']),
                'medium_count': len([i for i in issues if i.get('severity') == 'Medium']),
                'low_count': len([i for i in issues if i.get('severity') == 'Low']),
                'overall_risk': 'High' if len([i for i in issues if i.get('severity') in ['Critical', 'High']]) > 0 else 'Medium',
                'llm_analyzed': True
            }
        }
        
        scan_file = os.path.join(self.scan_dir, f'{sid}.json')
        try:
            with open(scan_file, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, ensure_ascii=False, indent=2)
            print(f"Scan results saved to: {scan_file}")
        except Exception as e:
            print(f"Error saving scan file: {e}")
        
        return sid
    
    def _generate_comprehensive_findings(self, target_url: str) -> List[Dict[str, Any]]:
        """Generate comprehensive mock findings for testing"""
        issues = [
            {
                'id': 'F-001',
                'title': 'Reflected XSS in search parameter',
                'risk': 'High',
                'url': f"{target_url}/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                'parameter': 'q',
                'evidence': ['<script>alert(1)</script>'],
                'recommendation': 'Escape output properly',
                'owasp_ref': 'A03:2021-Injection',
                'cwe': 'CWE-79',
                'request': {
                    'method': 'GET',
                    'url': f"{target_url}/search?q=<script>alert(1)</script>",
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Cookie': 'session=abc123'
                    },
                    'body': ''
                },
                'response': {
                    'status': 200,
                    'headers': {
                        'Content-Type': 'text/html; charset=utf-8',
                        'Server': 'Apache/2.4.58',
                        'Set-Cookie': 'session=abc123; Path=/'
                    },
                    'body': f'<html><body><h1>Search results for: <script>alert(1)</script></h1><p>No results found</p></body></html>'
                }
            },
            {
                'id': 'F-002',
                'title': 'SQL injection in login form',
                'risk': 'Critical',
                'url': f"{target_url}/login",
                'parameter': 'username',
                'evidence': ['MySQL error: You have an error in your SQL syntax'],
                'recommendation': 'Use parameterized queries',
                'owasp_ref': 'A03:2021-Injection',
                'cwe': 'CWE-89',
                'request': {
                    'method': 'POST',
                    'url': f"{target_url}/login",
                    'headers': {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    'body': 'username=admin\' OR \'1\'=\'1\' --&password=test'
                },
                'response': {
                    'status': 500,
                    'headers': {
                        'Content-Type': 'text/html; charset=utf-8',
                        'Server': 'Apache/2.4.58'
                    },
                    'body': '<html><body><h1>Error 500</h1><p>MySQL error: You have an error in your SQL syntax near \'--\' at line 1</p></body></html>'
                }
            },
            {
                'id': 'F-003',
                'title': 'Missing security headers',
                'risk': 'Medium',
                'url': f"{target_url}/",
                'parameter': None,
                'evidence': ['Missing Content-Security-Policy', 'Missing X-Frame-Options'],
                'recommendation': 'Add security headers',
                'owasp_ref': 'A05:2021-Security Misconfiguration',
                'cwe': 'CWE-693',
                'request': {
                    'method': 'GET',
                    'url': f"{target_url}/",
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    },
                    'body': ''
                },
                'response': {
                    'status': 200,
                    'headers': {
                        'Content-Type': 'text/html; charset=utf-8',
                        'Server': 'Apache/2.4.58'
                    },
                    'body': '<html><head><title>Home</title></head><body><h1>Welcome</h1></body></html>'
                }
            },
            {
                'id': 'F-004',
                'title': 'Path traversal vulnerability',
                'risk': 'High',
                'url': f"{target_url}/file?path=../../../etc/passwd",
                'parameter': 'path',
                'evidence': ['root:x:0:0:root:/root:/bin/bash'],
                'recommendation': 'Validate file paths',
                'owasp_ref': 'A01:2021-Broken Access Control',
                'cwe': 'CWE-22',
                'request': {
                    'method': 'GET',
                    'url': f"{target_url}/file?path=../../../etc/passwd",
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    'body': ''
                },
                'response': {
                    'status': 200,
                    'headers': {
                        'Content-Type': 'text/plain',
                        'Server': 'Apache/2.4.58'
                    },
                    'body': 'root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin'
                }
            },
            {
                'id': 'F-005',
                'title': 'Command injection in ping parameter',
                'risk': 'Critical',
                'url': f"{target_url}/ping?host=127.0.0.1;id",
                'parameter': 'host',
                'evidence': ['uid=0(root) gid=0(root) groups=0(root)'],
                'recommendation': 'Validate and sanitize input',
                'owasp_ref': 'A03:2021-Injection',
                'cwe': 'CWE-78',
                'request': {
                    'method': 'GET',
                    'url': f"{target_url}/ping?host=127.0.0.1;id",
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    'body': ''
                },
                'response': {
                    'status': 200,
                    'headers': {
                        'Content-Type': 'text/html; charset=utf-8',
                        'Server': 'Apache/2.4.58'
                    },
                    'body': '<html><body><h1>Ping Results</h1><pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\nuid=0(root) gid=0(root) groups=0(root)</pre></body></html>'
                }
            },
            {
                'id': 'F-006',
                'title': 'Open redirect vulnerability',
                'risk': 'Medium',
                'url': f"{target_url}/redirect?url=https://evil.com",
                'parameter': 'url',
                'evidence': ['Location: https://evil.com'],
                'recommendation': 'Validate redirect URLs',
                'owasp_ref': 'A01:2021-Broken Access Control',
                'cwe': 'CWE-601',
                'request': {
                    'method': 'GET',
                    'url': f"{target_url}/redirect?url=https://evil.com",
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    },
                    'body': ''
                },
                'response': {
                    'status': 302,
                    'headers': {
                        'Location': 'https://evil.com',
                        'Server': 'Apache/2.4.58'
                    },
                    'body': ''
                }
            }
        ]
        
        return issues
    
    def get_issues(self, scan_id):
        scan_file = os.path.join(self.scan_dir, f'{scan_id}.json')
        try:
            with open(scan_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('issues', [])
        except Exception:
            return []
    
    def get_scan_details(self, scan_id):
        scan_file = os.path.join(self.scan_dir, f'{scan_id}.json')
        try:
            with open(scan_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
