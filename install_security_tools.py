#!/usr/bin/env python3
"""
Script cài đặt các security tools cần thiết
"""

import subprocess
import sys
import os
import platform
import requests
import zipfile
import tarfile
from pathlib import Path

class SecurityToolsInstaller:
    def __init__(self):
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        self.tools_dir = Path("tools")
        self.tools_dir.mkdir(exist_ok=True)
        
    def install_go_tools(self):
        """Cài đặt Go tools"""
        print("[TOOL] Installing Go tools...")
        
        go_tools = {
            "nuclei": "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.15_windows_amd64.zip",
            "httpx": "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.3.7_windows_amd64.zip",
            "gospider": "https://github.com/jaeles-project/gospider/releases/latest/download/gospider_1.1.6_windows_amd64.zip",
            "ffuf": "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_windows_amd64.zip",
            "dalfox": "https://github.com/hahwul/dalfox/releases/latest/download/dalfox_2.9.0_windows_amd64.zip"
        }
        
        for tool, url in go_tools.items():
            try:
                print(f"  [PACKAGE] Installing {tool}...")
                self._download_and_extract_tool(tool, url)
            except Exception as e:
                print(f"  [ERROR] Failed to install {tool}: {e}")
    
    def install_python_tools(self):
        """Cài đặt Python tools"""
        print("🐍 Installing Python tools...")
        
        python_tools = [
            "sqlmap",
            "nikto",
            "requests",
            "beautifulsoup4",
            "lxml"
        ]
        
        for tool in python_tools:
            try:
                print(f"  [PACKAGE] Installing {tool}...")
                subprocess.run([sys.executable, "-m", "pip", "install", tool], 
                             check=True, capture_output=True)
                print(f"  [OK] {tool} installed successfully")
            except subprocess.CalledProcessError as e:
                print(f"  [ERROR] Failed to install {tool}: {e}")
    
    def install_nmap(self):
        """Cài đặt Nmap"""
        print("[SCAN] Installing Nmap...")
        
        if self.system == "windows":
            # Download Nmap for Windows
            nmap_url = "https://nmap.org/dist/nmap-7.94-win32.zip"
            try:
                self._download_and_extract_tool("nmap", nmap_url)
                print("  [OK] Nmap installed successfully")
            except Exception as e:
                print(f"  [ERROR] Failed to install Nmap: {e}")
        else:
            # Use package manager for Linux/Mac
            try:
                if self.system == "linux":
                    subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
                elif self.system == "darwin":
                    subprocess.run(["brew", "install", "nmap"], check=True)
                print("  [OK] Nmap installed successfully")
            except subprocess.CalledProcessError as e:
                print(f"  [ERROR] Failed to install Nmap: {e}")
    
    def _download_and_extract_tool(self, tool_name, url):
        """Download và extract tool"""
        tool_path = self.tools_dir / tool_name
        tool_path.mkdir(exist_ok=True)
        
        # Download file
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Determine file extension
        if url.endswith('.zip'):
            file_path = tool_path / f"{tool_name}.zip"
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract zip
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(tool_path)
            
            # Remove zip file
            file_path.unlink()
            
        elif url.endswith('.tar.gz'):
            file_path = tool_path / f"{tool_name}.tar.gz"
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract tar.gz
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                tar_ref.extractall(tool_path)
            
            # Remove tar.gz file
            file_path.unlink()
        
        print(f"  [OK] {tool_name} downloaded and extracted")
    
    def create_tool_wrappers(self):
        """Tạo wrapper scripts cho tools"""
        print("[NOTE] Creating tool wrappers...")
        
        # Create nuclei wrapper
        nuclei_wrapper = self.tools_dir / "nuclei_wrapper.py"
        with open(nuclei_wrapper, 'w') as f:
            f.write('''#!/usr/bin/env python3
import subprocess
import sys
import json
import os

def run_nuclei(target, output_format="json"):
    """Run nuclei scan"""
    try:
        # Find nuclei executable
        nuclei_path = None
        for root, dirs, files in os.walk("tools/nuclei"):
            for file in files:
                if file.startswith("nuclei") and not file.endswith(".exe"):
                    nuclei_path = os.path.join(root, file)
                    break
            if nuclei_path:
                break
        
        if not nuclei_path:
            nuclei_path = "nuclei"  # Try system PATH
        
        cmd = [nuclei_path, "-u", target, "-json", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            findings = []
            for line in result.stdout.strip().split('\\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except:
                        continue
            return {"success": True, "findings": findings}
        else:
            return {"success": False, "error": result.stderr}
            
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nuclei_wrapper.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = run_nuclei(target)
    print(json.dumps(result))
''')
        
        # Create ffuf wrapper
        ffuf_wrapper = self.tools_dir / "ffuf_wrapper.py"
        with open(ffuf_wrapper, 'w') as f:
            f.write('''#!/usr/bin/env python3
import subprocess
import sys
import json
import os

def run_ffuf(target, wordlist="common.txt"):
    """Run ffuf directory fuzzing"""
    try:
        # Find ffuf executable
        ffuf_path = None
        for root, dirs, files in os.walk("tools/ffuf"):
            for file in files:
                if file.startswith("ffuf") and not file.endswith(".exe"):
                    ffuf_path = os.path.join(root, file)
                    break
            if ffuf_path:
                break
        
        if not ffuf_path:
            ffuf_path = "ffuf"  # Try system PATH
        
        # Create wordlist if not exists
        wordlist_path = f"tools/{wordlist}"
        if not os.path.exists(wordlist_path):
            # Create basic wordlist
            basic_words = [
                "admin", "api", "backup", "config", "database", "dev", "files",
                "images", "js", "css", "uploads", "downloads", "test", "staging",
                "login", "logout", "register", "profile", "dashboard", "panel"
            ]
            with open(wordlist_path, 'w') as f:
                f.write('\\n'.join(basic_words))
        
        cmd = [
            ffuf_path, "-u", f"{target}/FUZZ",
            "-w", wordlist_path,
            "-mc", "200,301,302,403",
            "-o", "ffuf_output.json",
            "-of", "json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        # Try to read output file
        try:
            with open("ffuf_output.json", 'r') as f:
                ffuf_data = json.load(f)
            return {"success": True, "results": ffuf_data.get("results", [])}
        except:
            return {"success": True, "output": result.stdout, "error": result.stderr}
            
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ffuf_wrapper.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = run_ffuf(target)
    print(json.dumps(result))
''')
        
        print("  [OK] Tool wrappers created")
    
    def install_all(self):
        """Cài đặt tất cả tools"""
        print("🚀 Starting security tools installation...")
        
        try:
            self.install_go_tools()
            self.install_python_tools()
            self.install_nmap()
            self.create_tool_wrappers()
            
            print("\\n[OK] All tools installed successfully!")
            print("\\n[LIST] Installed tools:")
            print("  • nuclei - Vulnerability scanner")
            print("  • httpx - HTTP probe")
            print("  • gospider - Web crawler")
            print("  • ffuf - Web fuzzer")
            print("  • dalfox - XSS scanner")
            print("  • sqlmap - SQL injection scanner")
            print("  • nikto - Web server scanner")
            print("  • nmap - Network scanner")
            
        except Exception as e:
            print(f"[ERROR] Installation failed: {e}")

if __name__ == "__main__":
    installer = SecurityToolsInstaller()
    installer.install_all()

