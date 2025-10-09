"""
Real Security Tools Integration
Tích hợp các tool bảo mật thực tế: Nikto, Nuclei, FFUF
"""

import subprocess
import json
import tempfile
import os
import asyncio
from typing import List, Dict, Any


class RealToolsIntegration:
    """Class để tích hợp các tool bảo mật thực tế"""
    
    @staticmethod
    async def run_nikto_scan(target_url: str) -> List[Dict[str, Any]]:
        """Run Nikto scan and return vulnerabilities"""
        try:
            # Create temp file for Nikto output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_file = f.name
            
            # Run Nikto scan
            cmd = [
                'nikto', 
                '-h', target_url,
                '-Format', 'json',
                '-output', temp_file,
                '-timeout', '30',
                '-Tuning', '1,2,3,4,5,6,7,8,9'  # All tuning options
            ]
            
            print(f"[NIKTO] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # Read Nikto results
                if os.path.exists(temp_file):
                    with open(temp_file, 'r') as f:
                        nikto_data = json.load(f)
                    
                    vulnerabilities = []
                    if 'vulnerabilities' in nikto_data:
                        for vuln in nikto_data['vulnerabilities']:
                            vulnerabilities.append({
                                'type': 'nikto_finding',
                                'severity': 'medium',
                                'title': vuln.get('title', 'Nikto Finding'),
                                'description': vuln.get('description', ''),
                                'url': vuln.get('url', target_url),
                                'method': vuln.get('method', 'GET'),
                                'evidence': vuln.get('evidence', ''),
                                'tool': 'nikto',
                                'cve': vuln.get('cve', ''),
                                'osvdb': vuln.get('osvdb', '')
                            })
                    
                    os.unlink(temp_file)  # Clean up temp file
                    return vulnerabilities
                    
            except subprocess.TimeoutExpired:
                print("[NIKTO] Scan timeout")
            except FileNotFoundError:
                print("[NIKTO] Nikto not found, skipping")
            except Exception as e:
                print(f"[NIKTO] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[NIKTO] Scan failed: {e}")
        
        return []
    
    @staticmethod
    async def run_nuclei_scan(target_url: str) -> List[Dict[str, Any]]:
        """Run Nuclei scan and return vulnerabilities"""
        try:
            # Create temp file for Nuclei output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_file = f.name
            
            # Run Nuclei scan with common templates
            cmd = [
                'nuclei',
                '-u', target_url,
                '-json',
                '-o', temp_file,
                '-timeout', '30',
                '-templates', 'cves/',  # CVEs
                '-templates', 'exposures/',  # Exposures
                '-templates', 'vulnerabilities/',  # Vulnerabilities
                '-severity', 'critical,high,medium,low',  # All severities
                '-silent'  # Silent mode
            ]
            
            print(f"[NUCLEI] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                
                # Read Nuclei results
                if os.path.exists(temp_file):
                    vulnerabilities = []
                    with open(temp_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    nuclei_data = json.loads(line)
                                    vulnerabilities.append({
                                        'type': 'nuclei_finding',
                                        'severity': nuclei_data.get('info', {}).get('severity', 'medium'),
                                        'title': nuclei_data.get('info', {}).get('name', 'Nuclei Finding'),
                                        'description': nuclei_data.get('info', {}).get('description', ''),
                                        'url': nuclei_data.get('matched-at', target_url),
                                        'method': nuclei_data.get('info', {}).get('method', 'GET'),
                                        'evidence': nuclei_data.get('request', ''),
                                        'response': nuclei_data.get('response', ''),
                                        'tool': 'nuclei',
                                        'template_id': nuclei_data.get('template-id', ''),
                                        'cve': nuclei_data.get('info', {}).get('classification', {}).get('cve-id', ''),
                                        'cwe': nuclei_data.get('info', {}).get('classification', {}).get('cwe-id', '')
                                    })
                                except json.JSONDecodeError:
                                    continue
                    
                    os.unlink(temp_file)  # Clean up temp file
                    return vulnerabilities
                    
            except subprocess.TimeoutExpired:
                print("[NUCLEI] Scan timeout")
            except FileNotFoundError:
                print("[NUCLEI] Nuclei not found, skipping")
            except Exception as e:
                print(f"[NUCLEI] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[NUCLEI] Scan failed: {e}")
        
        return []
    
    @staticmethod
    async def run_ffuf_scan(target_url: str) -> List[Dict[str, Any]]:
        """Run FFUF directory fuzzing and return discovered paths"""
        try:
            # Create temp file for FFUF output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_file = f.name
            
            # Use built-in wordlist
            wordlist_path = "tools/wordlist.txt"
            if not os.path.exists(wordlist_path):
                # Create a basic wordlist if not exists
                basic_wordlist = [
                    "admin", "administrator", "login", "panel", "dashboard",
                    "config", "backup", "test", "dev", "api", "v1", "v2",
                    "upload", "files", "images", "css", "js", "assets",
                    "robots.txt", "sitemap.xml", ".env", "config.php",
                    "phpinfo.php", "info.php", "test.php", "debug.php"
                ]
                with open(wordlist_path, 'w') as f:
                    f.write('\n'.join(basic_wordlist))
            
            # Run FFUF scan
            cmd = [
                'tools/ffuf/ffuf.exe' if os.path.exists('tools/ffuf/ffuf.exe') else 'ffuf',
                '-u', f"{target_url}/FUZZ",
                '-w', wordlist_path,
                '-o', temp_file,
                '-of', 'json',
                '-mc', '200,301,302,403,500',  # Match codes
                '-fs', '0',  # Filter size 0 (no filtering)
                '-t', '10',  # 10 threads
                '-timeout', '10'  # 10 second timeout per request
            ]
            
            print(f"[FFUF] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # Read FFUF results
                if os.path.exists(temp_file):
                    with open(temp_file, 'r') as f:
                        ffuf_data = json.load(f)
                    
                    discovered_paths = []
                    if 'results' in ffuf_data:
                        for result in ffuf_data['results']:
                            discovered_paths.append({
                                'url': result.get('url', ''),
                                'status': result.get('status', 0),
                                'length': result.get('length', 0),
                                'words': result.get('words', 0),
                                'lines': result.get('lines', 0),
                                'content_type': result.get('content-type', ''),
                                'redirectlocation': result.get('redirectlocation', ''),
                                'tool': 'ffuf'
                            })
                    
                    os.unlink(temp_file)  # Clean up temp file
                    return discovered_paths
                    
            except subprocess.TimeoutExpired:
                print("[FFUF] Scan timeout")
            except FileNotFoundError:
                print("[FFUF] FFUF not found, skipping")
            except Exception as e:
                print(f"[FFUF] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[FFUF] Scan failed: {e}")
        
        return []
    
    @staticmethod
    async def run_httpx_scan(target_url: str) -> Dict[str, Any]:
        """Run HTTPX scan for basic HTTP analysis"""
        try:
            cmd = [
                'httpx',
                '-u', target_url,
                '-json',
                '-title',
                '-tech-detect',
                '-status-code',
                '-content-length',
                '-response-time',
                '-method', 'GET'
            ]
            
            print(f"[HTTPX] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.stdout:
                    try:
                        httpx_data = json.loads(result.stdout)
                        return {
                            'url': httpx_data.get('url', target_url),
                            'status_code': httpx_data.get('status-code', 0),
                            'title': httpx_data.get('title', ''),
                            'content_length': httpx_data.get('content-length', 0),
                            'response_time': httpx_data.get('response-time', ''),
                            'technologies': httpx_data.get('tech', []),
                            'tool': 'httpx'
                        }
                    except json.JSONDecodeError:
                        pass
                        
            except subprocess.TimeoutExpired:
                print("[HTTPX] Scan timeout")
            except FileNotFoundError:
                print("[HTTPX] HTTPX not found, skipping")
            except Exception as e:
                print(f"[HTTPX] Error: {e}")
                
        except Exception as e:
            print(f"[HTTPX] Scan failed: {e}")
        
        return {}
    
    @staticmethod
    async def run_gobuster_scan(target_url: str) -> List[Dict[str, Any]]:
        """Run Gobuster directory brute force"""
        try:
            import subprocess
            import tempfile
            import os
            
            # Create temp file for Gobuster output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                temp_file = f.name
            
            # Use common wordlist
            wordlist_path = "tools/wordlist.txt"
            if not os.path.exists(wordlist_path):
                basic_wordlist = [
                    "admin", "administrator", "login", "panel", "dashboard",
                    "config", "backup", "test", "dev", "api", "v1", "v2",
                    "upload", "files", "images", "css", "js", "assets",
                    "robots.txt", "sitemap.xml", ".env", "config.php",
                    "phpinfo.php", "info.php", "test.php", "debug.php"
                ]
                with open(wordlist_path, 'w') as f:
                    f.write('\n'.join(basic_wordlist))
            
            # Run Gobuster scan
            cmd = [
                'gobuster',
                'dir',
                '-u', target_url,
                '-w', wordlist_path,
                '-o', temp_file,
                '-t', '10',  # 10 threads
                '-x', 'php,html,txt,js,css',  # Extensions
                '-s', '200,204,301,302,307,401,403'  # Status codes
            ]
            
            print(f"[GOBUSTER] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # Read Gobuster results
                if os.path.exists(temp_file):
                    discovered_paths = []
                    with open(temp_file, 'r') as f:
                        for line in f:
                            if line.strip() and 'Status:' in line:
                                parts = line.strip().split()
                                if len(parts) >= 2:
                                    path = parts[0]
                                    status = parts[-1] if parts[-1].isdigit() else '200'
                                    discovered_paths.append({
                                        'path': path,
                                        'status': int(status),
                                        'tool': 'gobuster'
                                    })
                    
                    os.unlink(temp_file)
                    return discovered_paths
                    
            except subprocess.TimeoutExpired:
                print("[GOBUSTER] Scan timeout")
            except FileNotFoundError:
                print("[GOBUSTER] Gobuster not found, skipping")
            except Exception as e:
                print(f"[GOBUSTER] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[GOBUSTER] Scan failed: {e}")
        
        return []
    
    @staticmethod
    async def run_sqlmap_scan(target_url: str) -> List[Dict[str, Any]]:
        """Run SQLMap for SQL injection testing"""
        try:
            import subprocess
            import tempfile
            import os
            
            # Create temp file for SQLMap output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_file = f.name
            
            # Run SQLMap scan
            cmd = [
                'sqlmap',
                '-u', target_url,
                '--batch',
                '--risk=1',
                '--level=1',
                '--output-dir', os.path.dirname(temp_file),
                '--output-file', os.path.basename(temp_file),
                '--forms',
                '--crawl=2'
            ]
            
            print(f"[SQLMAP] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                # Read SQLMap results
                if os.path.exists(temp_file):
                    vulnerabilities = []
                    with open(temp_file, 'r') as f:
                        content = f.read()
                        if 'SQL injection' in content.lower():
                            vulnerabilities.append({
                                'type': 'sql_injection',
                                'url': target_url,
                                'severity': 'high',
                                'tool': 'sqlmap',
                                'evidence': 'SQL injection detected',
                                'description': 'Potential SQL injection vulnerability found'
                            })
                    
                    os.unlink(temp_file)
                    return vulnerabilities
                    
            except subprocess.TimeoutExpired:
                print("[SQLMAP] Scan timeout")
            except FileNotFoundError:
                print("[SQLMAP] SQLMap not found, skipping")
            except Exception as e:
                print(f"[SQLMAP] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[SQLMAP] Scan failed: {e}")
        
        return []
    
    @staticmethod
    async def run_dalfox_scan(target_url: str) -> List[Dict[str, Any]]:
        """Run Dalfox for XSS testing"""
        try:
            import subprocess
            import tempfile
            import os
            
            # Create temp file for Dalfox output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_file = f.name
            
            # Run Dalfox scan
            cmd = [
                'dalfox',
                'url', target_url,
                '--output', temp_file,
                '--format', 'json',
                '--silence'
            ]
            
            print(f"[DALFOX] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                
                # Read Dalfox results
                if os.path.exists(temp_file):
                    vulnerabilities = []
                    with open(temp_file, 'r') as f:
                        content = f.read()
                        if content.strip():
                            try:
                                import json
                                dalfox_data = json.loads(content)
                                if isinstance(dalfox_data, list):
                                    for vuln in dalfox_data:
                                        vulnerabilities.append({
                                            'type': 'xss',
                                            'url': vuln.get('url', target_url),
                                            'severity': 'medium',
                                            'tool': 'dalfox',
                                            'evidence': vuln.get('evidence', ''),
                                            'payload': vuln.get('payload', ''),
                                            'description': 'XSS vulnerability detected'
                                        })
                            except json.JSONDecodeError:
                                pass
                    
                    os.unlink(temp_file)
                    return vulnerabilities
                    
            except subprocess.TimeoutExpired:
                print("[DALFOX] Scan timeout")
            except FileNotFoundError:
                print("[DALFOX] Dalfox not found, skipping")
            except Exception as e:
                print(f"[DALFOX] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[DALFOX] Scan failed: {e}")
        
        return []
    
    @staticmethod
    async def run_subfinder_scan(target_url: str) -> List[Dict[str, Any]]:
        """Run Subfinder for subdomain enumeration"""
        try:
            import subprocess
            import tempfile
            import os
            from urllib.parse import urlparse
            
            # Extract domain from URL
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            
            # Create temp file for Subfinder output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                temp_file = f.name
            
            # Run Subfinder scan
            cmd = [
                'subfinder',
                '-d', domain,
                '-o', temp_file,
                '-silent'
            ]
            
            print(f"[SUBFINDER] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # Read Subfinder results
                if os.path.exists(temp_file):
                    subdomains = []
                    with open(temp_file, 'r') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain and '.' in subdomain:
                                subdomains.append({
                                    'subdomain': subdomain,
                                    'domain': domain,
                                    'tool': 'subfinder'
                                })
                    
                    os.unlink(temp_file)
                    return subdomains
                    
            except subprocess.TimeoutExpired:
                print("[SUBFINDER] Scan timeout")
            except FileNotFoundError:
                print("[SUBFINDER] Subfinder not found, skipping")
            except Exception as e:
                print(f"[SUBFINDER] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[SUBFINDER] Scan failed: {e}")
        
        return []
    
    @staticmethod
    async def run_whatweb_scan(target_url: str) -> Dict[str, Any]:
        """Run WhatWeb for technology detection"""
        try:
            import subprocess
            import tempfile
            import os
            import json
            
            # Create temp file for WhatWeb output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                temp_file = f.name
            
            # Run WhatWeb scan
            cmd = [
                'whatweb',
                target_url,
                '--log-json', temp_file,
                '--no-errors'
            ]
            
            print(f"[WHATWEB] Running: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # Read WhatWeb results
                if os.path.exists(temp_file):
                    technologies = {}
                    with open(temp_file, 'r') as f:
                        content = f.read()
                        if content.strip():
                            try:
                                data = json.loads(content)
                                if isinstance(data, list) and len(data) > 0:
                                    target_data = data[0]
                                    technologies = {
                                        'url': target_data.get('target', target_url),
                                        'status_code': target_data.get('status', 0),
                                        'technologies': target_data.get('plugins', {}),
                                        'server': target_data.get('server', 'Unknown'),
                                        'title': target_data.get('title', 'Unknown'),
                                        'tool': 'whatweb'
                                    }
                            except json.JSONDecodeError:
                                pass
                    
                    os.unlink(temp_file)
                    return technologies
                    
            except subprocess.TimeoutExpired:
                print("[WHATWEB] Scan timeout")
            except FileNotFoundError:
                print("[WHATWEB] WhatWeb not found, skipping")
            except Exception as e:
                print(f"[WHATWEB] Error: {e}")
            
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
        except Exception as e:
            print(f"[WHATWEB] Scan failed: {e}")
        
        return {}
    
    @staticmethod
    async def run_all_tools(target_url: str) -> Dict[str, Any]:
        """Run all available security tools with enhanced pipeline"""
        results = {
            'target_url': target_url,
            'nikto_results': [],
            'nuclei_results': [],
            'ffuf_results': [],
            'gobuster_results': [],
            'sqlmap_results': [],
            'dalfox_results': [],
            'subfinder_results': [],
            'whatweb_results': {},
            'httpx_results': {},
            'scan_time': None
        }
        
        import time
        start_time = time.time()
        
        # Run tools in parallel
        tasks = [
            RealToolsIntegration.run_nikto_scan(target_url),
            RealToolsIntegration.run_nuclei_scan(target_url),
            RealToolsIntegration.run_ffuf_scan(target_url),
            RealToolsIntegration.run_gobuster_scan(target_url),
            RealToolsIntegration.run_sqlmap_scan(target_url),
            RealToolsIntegration.run_dalfox_scan(target_url),
            RealToolsIntegration.run_subfinder_scan(target_url),
            RealToolsIntegration.run_whatweb_scan(target_url),
            RealToolsIntegration.run_httpx_scan(target_url)
        ]
        
        try:
            nikto_results, nuclei_results, ffuf_results, gobuster_results, sqlmap_results, dalfox_results, subfinder_results, whatweb_results, httpx_results = await asyncio.gather(
                *tasks, return_exceptions=True
            )
            
            results['nikto_results'] = nikto_results if not isinstance(nikto_results, Exception) else []
            results['nuclei_results'] = nuclei_results if not isinstance(nuclei_results, Exception) else []
            results['ffuf_results'] = ffuf_results if not isinstance(ffuf_results, Exception) else []
            results['gobuster_results'] = gobuster_results if not isinstance(gobuster_results, Exception) else []
            results['sqlmap_results'] = sqlmap_results if not isinstance(sqlmap_results, Exception) else []
            results['dalfox_results'] = dalfox_results if not isinstance(dalfox_results, Exception) else []
            results['subfinder_results'] = subfinder_results if not isinstance(subfinder_results, Exception) else []
            results['whatweb_results'] = whatweb_results if not isinstance(whatweb_results, Exception) else {}
            results['httpx_results'] = httpx_results if not isinstance(httpx_results, Exception) else {}
            
        except Exception as e:
            print(f"[TOOLS] Error running tools: {e}")
        
        results['scan_time'] = time.time() - start_time
        
        return results
