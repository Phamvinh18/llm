#!/usr/bin/env python3
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
            for line in result.stdout.strip().split('\n'):
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
