#!/usr/bin/env python3
"""
Script to install enhanced security tools for the scan engine
"""
import subprocess
import sys
import os
import platform

def run_command(cmd, description):
    """Run command and handle errors"""
    print(f"[TOOL] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[OK] {description} - Success")
            return True
        else:
            print(f"[ERROR] {description} - Failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ERROR] {description} - Error: {str(e)}")
        return False

def install_go_tools():
    """Install Go-based tools"""
    tools = [
        ("go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest", "Nuclei"),
        ("go install github.com/ffuf/ffuf@latest", "FFuF"),
        ("go install github.com/jaeles-project/gospider@latest", "GoSpider"),
        ("go install github.com/hakluke/hakrawler@latest", "Hakrawler"),
        ("go install github.com/tomnomnom/waybackurls@latest", "WaybackURLs"),
        ("go install github.com/hakluke/hakrawler@latest", "Hakrawler"),
        ("go install github.com/lc/subjs@latest", "SubJS"),
        ("go install github.com/hakluke/hakrawler@latest", "Hakrawler")
    ]
    
    for cmd, name in tools:
        run_command(cmd, f"Installing {name}")

def install_python_tools():
    """Install Python-based tools"""
    tools = [
        ("pip install sqlmap", "SQLMap"),
        ("pip install nikto", "Nikto"),
        ("pip install dalfox", "Dalfox"),
        ("pip install httpx", "HTTPx"),
        ("pip install wafw00f", "WAFW00F")
    ]
    
    for cmd, name in tools:
        run_command(cmd, f"Installing {name}")

def install_system_tools():
    """Install system tools"""
    system = platform.system().lower()
    
    if system == "windows":
        # Windows installation
        tools = [
            ("choco install nmap", "Nmap (via Chocolatey)"),
            ("choco install curl", "Curl (via Chocolatey)")
        ]
    elif system == "linux":
        # Linux installation
        tools = [
            ("sudo apt update && sudo apt install -y nmap curl", "Nmap and Curl"),
            ("sudo apt install -y go", "Go language")
        ]
    else:
        # macOS installation
        tools = [
            ("brew install nmap", "Nmap (via Homebrew)"),
            ("brew install go", "Go language")
        ]
    
    for cmd, name in tools:
        run_command(cmd, f"Installing {name}")

def main():
    """Main installation function"""
    print("🚀 Enhanced Security Tools Installation")
    print("=" * 50)
    
    # Check if Go is installed
    if not run_command("go version", "Checking Go installation"):
        print("[WARNING] Go is not installed. Please install Go first:")
        print("   Windows: https://golang.org/dl/")
        print("   Linux: sudo apt install golang-go")
        print("   macOS: brew install go")
        return
    
    # Install system tools
    install_system_tools()
    
    # Install Go tools
    install_go_tools()
    
    # Install Python tools
    install_python_tools()
    
    print("\n[SUCCESS] Installation completed!")
    print("\n[LIST] Next steps:")
    print("1. Add Go bin directory to PATH")
    print("2. Restart your terminal")
    print("3. Test tools: nuclei -version, ffuf -V, etc.")
    print("4. Run the enhanced scan: /scan enhanced http://testphp.vulnweb.com")

if __name__ == "__main__":
    main()


