"""
Security Tools Manager - Professional wrapper for security scanning tools
"""

import os
import json
import subprocess
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

@dataclass
class ToolOutput:
    success: bool
    stdout: str
    stderr: str
    returncode: int
    execution_time: float
    output_file: Optional[str] = None

class SecurityToolsManager:
    def __init__(self):
        self.tools_available = self._check_tools_availability()
        self.data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    
    def _check_tools_availability(self) -> Dict[str, bool]:
        """Check which security tools are available"""
        tools = {
            'httpx': self._check_tool('httpx', ['-version']),
            'nuclei': self._check_tool('nuclei', ['-version']),
            'ffuf': self._check_tool('ffuf', ['-V']),
            'dalfox': self._check_tool('dalfox', ['version']),
            'gospider': self._check_tool('gospider', ['-h']),
            'nikto': self._check_tool('nikto', ['-Version']),
            'sqlmap': self._check_tool('sqlmap', ['--version']),
            'nmap': self._check_tool('nmap', ['--version']),
            'wafw00f': self._check_tool('wafw00f', ['--version'])
        }
        return tools
    
    def _check_tool(self, tool_name: str, version_args: List[str]) -> bool:
        """Check if a specific tool is available"""
        try:
            result = subprocess.run(
                [tool_name] + version_args,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get list of available tools"""
        return self.tools_available.copy()
    
    def run_httpx_scan(self, target_url: str, output_dir: str) -> ToolOutput:
        """Run httpx for HTTP probing"""
        if not self.tools_available.get('httpx', False):
            return ToolOutput(False, "", "httpx not available", -1, 0)
        
        output_file = os.path.join(output_dir, 'httpx.json')
        cmd = [
            'httpx',
            '-silent',
            '-status-code',
            '-title',
            '-server',
            '-headers',
            '-json',
            '-o', output_file,
            target_url
        ]
        
        return self._run_tool(cmd, output_file)
    
    def run_nuclei_scan(self, target_url: str, output_dir: str, severity: str = "high,critical") -> ToolOutput:
        """Run nuclei for vulnerability scanning"""
        if not self.tools_available.get('nuclei', False):
            return ToolOutput(False, "", "nuclei not available", -1, 0)
        
        output_file = os.path.join(output_dir, 'nuclei.json')
        cmd = [
            'nuclei',
            '-u', target_url,
            '-severity', severity,
            '-json',
            '-o', output_file,
            '-silent'
        ]
        
        return self._run_tool(cmd, output_file)
    
    def run_ffuf_scan(self, target_url: str, output_dir: str, wordlist: str = "common") -> ToolOutput:
        """Run ffuf for directory fuzzing"""
        if not self.tools_available.get('ffuf', False):
            return ToolOutput(False, "", "ffuf not available", -1, 0)
        
        output_file = os.path.join(output_dir, 'ffuf.json')
        
        # Get wordlist path
        wordlist_path = self._get_wordlist_path(wordlist)
        if not wordlist_path:
            return ToolOutput(False, "", f"Wordlist {wordlist} not found", -1, 0)
        
        cmd = [
            'ffuf',
            '-u', f"{target_url}/FUZZ",
            '-w', wordlist_path,
            '-mc', '200,301,302,403',
            '-json',
            '-o', output_file,
            '-t', '20'
        ]
        
        return self._run_tool(cmd, output_file)
    
    def run_dalfox_scan(self, target_url: str, output_dir: str) -> ToolOutput:
        """Run dalfox for XSS scanning"""
        if not self.tools_available.get('dalfox', False):
            return ToolOutput(False, "", "dalfox not available", -1, 0)
        
        output_file = os.path.join(output_dir, 'dalfox.json')
        cmd = [
            'dalfox',
            'url', target_url,
            '--basic-payloads',
            '--skip-binary',
            '--output', output_file,
            '--format', 'json'
        ]
        
        return self._run_tool(cmd, output_file)
    
    def run_gospider_scan(self, target_url: str, output_dir: str) -> ToolOutput:
        """Run gospider for web crawling"""
        if not self.tools_available.get('gospider', False):
            return ToolOutput(False, "", "gospider not available", -1, 0)
        
        output_file = os.path.join(output_dir, 'gospider.txt')
        cmd = [
            'gospider',
            '-s', target_url,
            '-t', '10',
            '-o', output_dir,
            '--json'
        ]
        
        return self._run_tool(cmd, output_file)
    
    def run_nikto_scan(self, target_url: str, output_dir: str) -> ToolOutput:
        """Run nikto for web server scanning"""
        if not self.tools_available.get('nikto', False):
            return ToolOutput(False, "", "nikto not available", -1, 0)
        
        output_file = os.path.join(output_dir, 'nikto.txt')
        cmd = [
            'nikto',
            '-h', target_url,
            '-o', output_file,
            '-Format', 'txt'
        ]
        
        return self._run_tool(cmd, output_file)
    
    def run_sqlmap_scan(self, target_url: str, output_dir: str) -> ToolOutput:
        """Run sqlmap for SQL injection scanning"""
        if not self.tools_available.get('sqlmap', False):
            return ToolOutput(False, "", "sqlmap not available", -1, 0)
        
        cmd = [
            'sqlmap',
            '-u', target_url,
            '--batch',
            '--level=2',
            '--risk=1',
            '--threads=2',
            '--output-dir', output_dir
        ]
        
        return self._run_tool(cmd, None)
    
    def run_nmap_scan(self, target_url: str, output_dir: str) -> ToolOutput:
        """Run nmap for port scanning"""
        if not self.tools_available.get('nmap', False):
            return ToolOutput(False, "", "nmap not available", -1, 0)
        
        # Extract hostname from URL
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        
        if not hostname:
            return ToolOutput(False, "", "Invalid hostname", -1, 0)
        
        output_file = os.path.join(output_dir, 'nmap.xml')
        cmd = [
            'nmap',
            '-Pn',
            '-sV',
            '-p', '80,443,8080,8443',
            '--script', 'http-enum',
            '-oX', output_file,
            hostname
        ]
        
        return self._run_tool(cmd, output_file)
    
    def run_wafw00f_scan(self, target_url: str, output_dir: str) -> ToolOutput:
        """Run wafw00f for WAF detection"""
        if not self.tools_available.get('wafw00f', False):
            return ToolOutput(False, "", "wafw00f not available", -1, 0)
        
        output_file = os.path.join(output_dir, 'wafw00f.txt')
        cmd = [
            'wafw00f',
            target_url,
            '-o', output_file
        ]
        
        return self._run_tool(cmd, output_file)
    
    def _run_tool(self, cmd: List[str], output_file: Optional[str]) -> ToolOutput:
        """Run a tool command and return results"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=os.getcwd()
            )
            
            execution_time = time.time() - start_time
            
            return ToolOutput(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                execution_time=execution_time,
                output_file=output_file
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return ToolOutput(
                success=False,
                stdout="",
                stderr="Command timed out",
                returncode=-1,
                execution_time=execution_time,
                output_file=output_file
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return ToolOutput(
                success=False,
                stdout="",
                stderr=str(e),
                returncode=-1,
                execution_time=execution_time,
                output_file=output_file
            )
    
    def _get_wordlist_path(self, wordlist: str) -> Optional[str]:
        """Get path to wordlist file"""
        wordlist_paths = {
            'common': '/usr/share/wordlists/dirb/common.txt',
            'big': '/usr/share/wordlists/dirb/big.txt',
            'small': '/usr/share/wordlists/dirb/small.txt',
            'medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        }
        
        path = wordlist_paths.get(wordlist)
        if path and os.path.exists(path):
            return path
        
        # Try alternative paths
        alternative_paths = [
            f'/usr/share/wordlists/{wordlist}.txt',
            f'/usr/share/wordlists/dirb/{wordlist}.txt',
            f'./wordlists/{wordlist}.txt'
        ]
        
        for alt_path in alternative_paths:
            if os.path.exists(alt_path):
                return alt_path
        
        return None
    
    def run_fast_scan(self, target_url: str, output_dir: str) -> Dict[str, ToolOutput]:
        """Run fast scan profile"""
        results = {}
        
        # HTTP check
        results['httpx'] = self.run_httpx_scan(target_url, output_dir)
        
        # WAF detection
        results['wafw00f'] = self.run_wafw00f_scan(target_url, output_dir)
        
        # Basic nuclei scan
        results['nuclei'] = self.run_nuclei_scan(target_url, output_dir, "critical,high")
        
        # Basic directory fuzzing
        results['ffuf'] = self.run_ffuf_scan(target_url, output_dir, "common")
        
        # Basic XSS scan
        results['dalfox'] = self.run_dalfox_scan(target_url, output_dir)
        
        return results
    
    def run_enhanced_scan(self, target_url: str, output_dir: str) -> Dict[str, ToolOutput]:
        """Run enhanced scan profile"""
        results = {}
        
        # All fast scan tools
        fast_results = self.run_fast_scan(target_url, output_dir)
        results.update(fast_results)
        
        # Additional tools for enhanced scan
        results['gospider'] = self.run_gospider_scan(target_url, output_dir)
        results['nikto'] = self.run_nikto_scan(target_url, output_dir)
        results['nmap'] = self.run_nmap_scan(target_url, output_dir)
        
        # Enhanced nuclei scan
        results['nuclei_enhanced'] = self.run_nuclei_scan(target_url, output_dir, "medium,high,critical")
        
        return results
    
    def run_deep_scan(self, target_url: str, output_dir: str) -> Dict[str, ToolOutput]:
        """Run deep scan profile"""
        results = {}
        
        # All enhanced scan tools
        enhanced_results = self.run_enhanced_scan(target_url, output_dir)
        results.update(enhanced_results)
        
        # Additional tools for deep scan
        results['sqlmap'] = self.run_sqlmap_scan(target_url, output_dir)
        
        # Deep nuclei scan
        results['nuclei_deep'] = self.run_nuclei_scan(target_url, output_dir, "info,low,medium,high,critical")
        
        return results

