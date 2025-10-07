#!/usr/bin/env python3
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
                f.write('\n'.join(basic_words))
        
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
