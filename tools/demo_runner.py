#!/usr/bin/env python3
import requests, time
API='http://localhost:8001/api'
print('Triggering demo intent...')
r = requests.post(API + '/intent/handle', json={'session_id':'demo','text':'Hãy scan http://juice-shop:3000'})
print('Response:', r.status_code, r.text)
try:
    time.sleep(1)
    r = requests.post(API + '/scan/issues', json={'scan_id':'mock-scan'})
    print('Issues:', r.status_code, r.text)
except Exception as e:
    print('No issues:', e)
