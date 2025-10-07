"""
Security Tools Wrappers - Tích hợp thực tế các security tools
"""

import subprocess
import json
import os
import time
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
import tempfile
import shutil

class SecurityTool:
    """Base class cho security tools"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.tools_dir = Path("tools")
        self.executable_path = self._find_executable()
    
    def _find_executable(self) -> Optional[str]:
        """Tìm executable của tool"""
        # Check system PATH first
        try:
            result = subprocess.run([self.tool_name, "--version"], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                return self.tool_name
        except:
            pass
        
        # Check tools directory
        if self.tools_dir.exists():
            for root, dirs, files in os.walk(self.tools_dir / self.tool_name):
                for file in files:
                    if file.startswith(self.tool_name) and not file.endswith(".exe"):
                        return os.path.join(root, file)
        
        return None
    
    def is_available(self) -> bool:
        """Kiểm tra tool có sẵn không"""
        return self.executable_path is not None
    
    def run_command(self, cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Chạy command với timeout"""
        try:
            if not self.is_available():
                return {"success": False, "error": f"{self.tool_name} not available"}
            
            result = subprocess.run(
                [self.executable_path] + cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"{self.tool_name} timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

class NucleiScanner(SecurityTool):
    """Nuclei vulnerability scanner"""
    
    def __init__(self):
        super().__init__("nuclei")
    
    def scan_target(self, target: str, templates: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan target với nuclei"""
        cmd = ["-u", target, "-json", "-silent"]
        
        if templates:
            cmd.extend(["-t", ",".join(templates)])
        
        result = self.run_command(cmd, timeout=300)
        
        if result["success"] and result["stdout"]:
            findings = []
            for line in result["stdout"].strip().split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except:
                        continue
            return {"success": True, "findings": findings}
        
        return result

class HTTPXScanner(SecurityTool):
    """HTTPX HTTP probe"""
    
    def __init__(self):
        super().__init__("httpx")
    
    def probe_target(self, target: str) -> Dict[str, Any]:
        """Probe target với httpx"""
        cmd = ["-u", target, "-json", "-silent"]
        
        result = self.run_command(cmd, timeout=30)
        
        if result["success"] and result["stdout"]:
            try:
                data = json.loads(result["stdout"])
                return {"success": True, "data": data}
            except:
                return {"success": True, "output": result["stdout"]}
        
        return result

class FFUFFuzzer(SecurityTool):
    """FFUF web fuzzer"""
    
    def __init__(self):
        super().__init__("ffuf")
        self.wordlist_path = self._create_wordlist()
    
    def _create_wordlist(self) -> str:
        """Tạo wordlist cơ bản"""
        wordlist_path = self.tools_dir / "wordlist.txt"
        
        if not wordlist_path.exists():
            basic_words = [
                "admin", "api", "backup", "config", "database", "dev", "files",
                "images", "js", "css", "uploads", "downloads", "test", "staging",
                "login", "logout", "register", "profile", "dashboard", "panel",
                "wp-admin", "phpmyadmin", "admin.php", "config.php", "readme.txt",
                "robots.txt", "sitemap.xml", "crossdomain.xml", ".env", ".git",
                "backup.sql", "database.sql", "dump.sql", "test.php", "info.php"
            ]
            
            with open(wordlist_path, 'w') as f:
                f.write('\n'.join(basic_words))
        
        return str(wordlist_path)
    
    def fuzz_directories(self, target: str) -> Dict[str, Any]:
        """Fuzz directories với ffuf"""
        output_file = f"ffuf_output_{int(time.time())}.json"
        
        cmd = [
            "-u", f"{target}/FUZZ",
            "-w", self.wordlist_path,
            "-mc", "200,301,302,403",
            "-o", output_file,
            "-of", "json"
        ]
        
        result = self.run_command(cmd, timeout=180)
        
        # Try to read output file
        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    ffuf_data = json.load(f)
                os.remove(output_file)  # Clean up
                return {"success": True, "results": ffuf_data.get("results", [])}
        except:
            pass
        
        return result

class DalfoxScanner(SecurityTool):
    """Dalfox XSS scanner"""
    
    def __init__(self):
        super().__init__("dalfox")
    
    def scan_xss(self, target: str) -> Dict[str, Any]:
        """Scan XSS với dalfox"""
        cmd = ["url", target, "--format", "json"]
        
        result = self.run_command(cmd, timeout=180)
        
        if result["success"] and result["stdout"]:
            try:
                findings = json.loads(result["stdout"])
                return {"success": True, "findings": findings}
            except:
                return {"success": True, "output": result["stdout"]}
        
        return result

class SQLMapScanner(SecurityTool):
    """SQLMap SQL injection scanner"""
    
    def __init__(self):
        super().__init__("sqlmap")
    
    def scan_sql_injection(self, target: str) -> Dict[str, Any]:
        """Scan SQL injection với sqlmap"""
        output_dir = f"sqlmap_output_{int(time.time())}"
        
        cmd = [
            "-u", target,
            "--batch", "--level=1", "--risk=1",
            "--output-dir", output_dir
        ]
        
        result = self.run_command(cmd, timeout=180)
        
        # Try to read output files
        try:
            if os.path.exists(output_dir):
                # Look for log files
                for file in os.listdir(output_dir):
                    if file.endswith('.log'):
                        with open(os.path.join(output_dir, file), 'r') as f:
                            log_content = f.read()
                        shutil.rmtree(output_dir)  # Clean up
                        return {"success": True, "log": log_content}
                shutil.rmtree(output_dir)  # Clean up
        except:
            pass
        
        return result

class NiktoScanner(SecurityTool):
    """Nikto web server scanner"""
    
    def __init__(self):
        super().__init__("nikto")
    
    def scan_server(self, target: str) -> Dict[str, Any]:
        """Scan server với nikto"""
        output_file = f"nikto_output_{int(time.time())}.txt"
        
        cmd = ["-h", target, "-output", output_file]
        
        result = self.run_command(cmd, timeout=300)
        
        # Try to read output file
        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    output_content = f.read()
                os.remove(output_file)  # Clean up
                return {"success": True, "output": output_content}
        except:
            pass
        
        return result

class NmapScanner(SecurityTool):
    """Nmap network scanner"""
    
    def __init__(self):
        super().__init__("nmap")
    
    def scan_ports(self, target: str) -> Dict[str, Any]:
        """Scan ports với nmap"""
        cmd = ["-Pn", "-sV", "-p-", "--min-rate=1000", "-oX", "nmap_output.xml"]
        
        # Extract host from URL
        if target.startswith("http://"):
            host = target[7:].split('/')[0]
        elif target.startswith("https://"):
            host = target[8:].split('/')[0]
        else:
            host = target.split('/')[0]
        
        cmd.insert(-2, host)  # Insert host before output file
        
        result = self.run_command(cmd, timeout=300)
        
        # Try to read XML output
        try:
            if os.path.exists("nmap_output.xml"):
                with open("nmap_output.xml", 'r') as f:
                    xml_content = f.read()
                os.remove("nmap_output.xml")  # Clean up
                return {"success": True, "xml": xml_content}
        except:
            pass
        
        return result

class GospiderCrawler(SecurityTool):
    """Gospider web crawler"""
    
    def __init__(self):
        super().__init__("gospider")
    
    def crawl_target(self, target: str) -> Dict[str, Any]:
        """Crawl target với gospider"""
        output_dir = f"gospider_output_{int(time.time())}"
        
        cmd = ["-s", target, "-o", output_dir, "--json"]
        
        result = self.run_command(cmd, timeout=120)
        
        # Try to read output files
        try:
            if os.path.exists(output_dir):
                urls = []
                for file in os.listdir(output_dir):
                    if file.endswith('.json'):
                        with open(os.path.join(output_dir, file), 'r') as f:
                            content = f.read()
                            if content.strip():
                                try:
                                    data = json.loads(content)
                                    urls.append(data)
                                except:
                                    pass
                shutil.rmtree(output_dir)  # Clean up
                return {"success": True, "urls": urls}
        except:
            pass
        
        return result

class SecurityToolsManager:
    """Manager cho tất cả security tools"""
    
    def __init__(self):
        self.tools = {
            "nuclei": NucleiScanner(),
            "httpx": HTTPXScanner(),
            "ffuf": FFUFFuzzer(),
            "dalfox": DalfoxScanner(),
            "sqlmap": SQLMapScanner(),
            "nikto": NiktoScanner(),
            "nmap": NmapScanner(),
            "gospider": GospiderCrawler()
        }
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Lấy danh sách tools có sẵn"""
        return {name: tool.is_available() for name, tool in self.tools.items()}
    
    def run_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Chạy reconnaissance"""
        results = {}
        
        # HTTPX probe
        if self.tools["httpx"].is_available():
            results["httpx"] = self.tools["httpx"].probe_target(target)
        
        # Basic HTTP requests
        try:
            response = requests.head(target, timeout=10, allow_redirects=True)
            results["http_probe"] = {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "url": response.url
            }
        except Exception as e:
            results["http_probe"] = {"success": False, "error": str(e)}
        
        return results
    
    def run_crawling(self, target: str) -> Dict[str, Any]:
        """Chạy crawling"""
        results = {}
        
        # Gospider
        if self.tools["gospider"].is_available():
            results["gospider"] = self.tools["gospider"].crawl_target(target)
        
        # Basic crawling with requests
        try:
            response = requests.get(target, timeout=10)
            if response.status_code == 200:
                # Simple link extraction
                import re
                links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                results["basic_crawl"] = {
                    "success": True,
                    "links": links[:50],  # Limit to 50 links
                    "status_code": response.status_code
                }
        except Exception as e:
            results["basic_crawl"] = {"success": False, "error": str(e)}
        
        return results
    
    def run_directory_fuzzing(self, target: str) -> Dict[str, Any]:
        """Chạy directory fuzzing"""
        results = {}
        
        # FFUF
        if self.tools["ffuf"].is_available():
            results["ffuf"] = self.tools["ffuf"].fuzz_directories(target)
        
        # Basic directory checking
        common_paths = [
            "/admin", "/login", "/api", "/test", "/dev", "/staging",
            "/robots.txt", "/sitemap.xml", "/favicon.ico", "/.env"
        ]
        
        basic_results = []
        for path in common_paths:
            try:
                url = target.rstrip('/') + path
                response = requests.head(url, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    basic_results.append({
                        "url": url,
                        "status": response.status_code,
                        "length": response.headers.get('content-length', 0)
                    })
            except:
                continue
        
        results["basic_fuzz"] = {"success": True, "results": basic_results}
        
        return results
    
    def run_vulnerability_scanning(self, target: str) -> Dict[str, Any]:
        """Chạy vulnerability scanning"""
        results = {}
        
        # Nuclei
        if self.tools["nuclei"].is_available():
            results["nuclei"] = self.tools["nuclei"].scan_target(target)
        
        # Dalfox (XSS)
        if self.tools["dalfox"].is_available():
            results["dalfox"] = self.tools["dalfox"].scan_xss(target)
        
        # SQLMap
        if self.tools["sqlmap"].is_available():
            results["sqlmap"] = self.tools["sqlmap"].scan_sql_injection(target)
        
        # Nikto
        if self.tools["nikto"].is_available():
            results["nikto"] = self.tools["nikto"].scan_server(target)
        
        return results
    
    def run_port_scanning(self, target: str) -> Dict[str, Any]:
        """Chạy port scanning"""
        results = {}
        
        # Nmap
        if self.tools["nmap"].is_available():
            results["nmap"] = self.tools["nmap"].scan_ports(target)
        
        return results

