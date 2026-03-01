import urllib.request
import json
import sys

data = {
    "targets": "127.0.0.1",
    "ports": [80, 443],
    "run_vuln_check": True,
    "take_screenshots": True
}

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/scan/target',
    method='POST',
    headers={'Content-Type': 'application/json'},
    data=json.dumps(data).encode('utf-8')
)

try:
    res = urllib.request.urlopen(req)
    print("SUCCESS:", res.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print(f"Error {e.code}: {e.read().decode('utf-8')}")
except Exception as e:
    print(f"Exception: {e}")
