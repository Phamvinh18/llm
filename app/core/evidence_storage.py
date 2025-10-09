"""
Evidence Storage System - Quản lý lưu trữ evidence và raw outputs
"""

import json
import os
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import requests
from urllib.parse import urlparse, urljoin
import hashlib

@dataclass
class EvidenceItem:
    id: str
    finding_id: str
    type: str  # screenshot, har, request_response, raw_output
    file_path: str
    metadata: Dict[str, Any]
    created_at: str

class EvidenceStorage:
    """Quản lý lưu trữ evidence cho scan findings"""
    
    def __init__(self, base_dir: str = "reports"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
    
    def create_evidence_dir(self, job_id: str) -> Path:
        """Tạo thư mục evidence cho job"""
        evidence_dir = self.base_dir / job_id / "raw"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        return evidence_dir
    
    async def capture_screenshot(self, url: str, job_id: str, finding_id: str) -> Optional[str]:
        """Capture screenshot của URL"""
        try:
            evidence_dir = self.create_evidence_dir(job_id)
            screenshot_path = evidence_dir / f"screenshot_{finding_id}.png"
            
            # Sử dụng Playwright để capture screenshot
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, wait_until='networkidle')
                await page.screenshot(path=str(screenshot_path), full_page=True)
                await browser.close()
            
            return str(screenshot_path)
            
        except Exception as e:
            print(f"Screenshot capture error: {e}")
            return None
    
    async def capture_har(self, url: str, job_id: str, finding_id: str) -> Optional[str]:
        """Capture HAR file cho request/response"""
        try:
            evidence_dir = self.create_evidence_dir(job_id)
            har_path = evidence_dir / f"har_{finding_id}.har"
            
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Start HAR recording
                await page.route("**/*", lambda route: route.continue_())
                
                # Navigate and capture
                response = await page.goto(url, wait_until='networkidle')
                
                # Get HAR data
                har_data = await page.evaluate("""() => {
                    return JSON.stringify(performance.getEntriesByType('navigation'));
                }""")
                
                # Save HAR
                with open(har_path, 'w', encoding='utf-8') as f:
                    f.write(har_data)
                
                await browser.close()
            
            return str(har_path)
            
        except Exception as e:
            print(f"HAR capture error: {e}")
            return None
    
    def save_request_response(self, url: str, method: str, headers: Dict, data: Any, 
                            response_text: str, response_headers: Dict, 
                            job_id: str, finding_id: str) -> str:
        """Save request/response data"""
        evidence_dir = self.create_evidence_dir(job_id)
        req_res_path = evidence_dir / f"req_res_{finding_id}.json"
        
        req_res_data = {
            "request": {
                "url": url,
                "method": method,
                "headers": headers,
                "data": data,
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ')
            },
            "response": {
                "status_code": 200,  # Will be updated with actual status
                "headers": response_headers,
                "body": response_text[:10000],  # Limit size
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ')
            }
        }
        
        with open(req_res_path, 'w', encoding='utf-8') as f:
            json.dump(req_res_data, f, indent=2, ensure_ascii=False)
        
        return str(req_res_path)
    
    def extract_evidence_snippet(self, response_text: str, marker: str, 
                               context_lines: int = 5) -> str:
        """Extract evidence snippet around marker"""
        try:
            lines = response_text.split('\n')
            marker_line = -1
            
            # Find marker line
            for i, line in enumerate(lines):
                if marker in line:
                    marker_line = i
                    break
            
            if marker_line == -1:
                return "Marker not found in response"
            
            # Extract context around marker
            start = max(0, marker_line - context_lines)
            end = min(len(lines), marker_line + context_lines + 1)
            
            snippet_lines = lines[start:end]
            
            # Highlight marker line
            for i, line in enumerate(snippet_lines):
                if marker in line:
                    snippet_lines[i] = f">>> {line} <<<"
                    break
            
            return '\n'.join(snippet_lines)
            
        except Exception as e:
            return f"Error extracting snippet: {str(e)}"
    
    def save_tool_output(self, tool_name: str, output: str, job_id: str) -> str:
        """Save raw tool output"""
        evidence_dir = self.create_evidence_dir(job_id)
        output_path = evidence_dir / f"{tool_name}.json"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(output)
        
        return str(output_path)
    
    def create_evidence_index(self, job_id: str, findings: List[Dict[str, Any]]) -> str:
        """Create evidence index for all findings"""
        evidence_dir = self.create_evidence_dir(job_id)
        index_path = evidence_dir / "evidence_index.json"
        
        evidence_items = []
        
        for finding in findings:
            finding_id = finding.get('id', '')
            
            # Collect all evidence for this finding
            finding_evidence = {
                "finding_id": finding_id,
                "type": finding.get('type', ''),
                "evidence_files": [],
                "screenshots": [],
                "har_files": [],
                "request_response": [],
                "raw_outputs": finding.get('raw_outputs', [])
            }
            
            # Check for evidence files
            for file_path in finding.get('raw_outputs', []):
                if os.path.exists(file_path):
                    finding_evidence["evidence_files"].append(file_path)
            
            # Check for screenshots
            screenshot_path = evidence_dir / f"screenshot_{finding_id}.png"
            if screenshot_path.exists():
                finding_evidence["screenshots"].append(str(screenshot_path))
            
            # Check for HAR files
            har_path = evidence_dir / f"har_{finding_id}.har"
            if har_path.exists():
                finding_evidence["har_files"].append(str(har_path))
            
            # Check for request/response
            req_res_path = evidence_dir / f"req_res_{finding_id}.json"
            if req_res_path.exists():
                finding_evidence["request_response"].append(str(req_res_path))
            
            evidence_items.append(finding_evidence)
        
        index_data = {
            "job_id": job_id,
            "created_at": time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "total_findings": len(findings),
            "evidence_items": evidence_items,
            "summary": {
                "total_screenshots": sum(len(item["screenshots"]) for item in evidence_items),
                "total_har_files": sum(len(item["har_files"]) for item in evidence_items),
                "total_request_response": sum(len(item["request_response"]) for item in evidence_items),
                "total_raw_outputs": sum(len(item["raw_outputs"]) for item in evidence_items)
            }
        }
        
        with open(index_path, 'w', encoding='utf-8') as f:
            json.dump(index_data, f, indent=2, ensure_ascii=False)
        
        return str(index_path)
    
    def get_evidence_summary(self, job_id: str) -> Dict[str, Any]:
        """Get evidence summary for a job"""
        evidence_dir = self.base_dir / job_id / "raw"
        index_path = evidence_dir / "evidence_index.json"
        
        if not index_path.exists():
            return {"error": "Evidence index not found"}
        
        try:
            with open(index_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            return {"error": f"Error reading evidence index: {str(e)}"}
    
    def cleanup_old_evidence(self, days_old: int = 30):
        """Cleanup old evidence files"""
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        
        for job_dir in self.base_dir.iterdir():
            if job_dir.is_dir():
                try:
                    # Check if job is old enough
                    job_time = job_dir.stat().st_mtime
                    if job_time < cutoff_time:
                        # Remove old job directory
                        import shutil
                        shutil.rmtree(job_dir)
                        print(f"Cleaned up old evidence: {job_dir}")
                except Exception as e:
                    print(f"Error cleaning up {job_dir}: {e}")
    
    def get_evidence_file(self, job_id: str, filename: str) -> Optional[str]:
        """Get path to specific evidence file"""
        evidence_dir = self.base_dir / job_id / "raw"
        file_path = evidence_dir / filename
        
        if file_path.exists():
            return str(file_path)
        return None
    
    def list_evidence_files(self, job_id: str) -> List[str]:
        """List all evidence files for a job"""
        evidence_dir = self.base_dir / job_id / "raw"
        
        if not evidence_dir.exists():
            return []
        
        files = []
        for file_path in evidence_dir.iterdir():
            if file_path.is_file():
                files.append(str(file_path))
        
        return sorted(files)
    
    def create_evidence_archive(self, job_id: str) -> Optional[str]:
        """Create archive of all evidence for a job"""
        try:
            import zipfile
            
            evidence_dir = self.base_dir / job_id / "raw"
            archive_path = self.base_dir / job_id / f"evidence_{job_id}.zip"
            
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in evidence_dir.rglob('*'):
                    if file_path.is_file():
                        arcname = file_path.relative_to(evidence_dir)
                        zipf.write(file_path, arcname)
            
            return str(archive_path)
            
        except Exception as e:
            print(f"Error creating evidence archive: {e}")
            return None
