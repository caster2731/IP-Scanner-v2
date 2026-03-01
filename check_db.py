import sqlite3
import json

try:
    conn = sqlite3.connect('d:/Myapp/ipscan/data/ipscan.db')
    conn.row_factory = sqlite3.Row
    res = conn.execute("SELECT ip, port, status_code, screenshot_path FROM scan_results WHERE ip = '93.184.216.34' ORDER BY id DESC LIMIT 5").fetchall()
    
    print("=== DB Verification (Tech Stack) ===")
    for r in res:
        print(dict(r))
        
except Exception as e:
    print(f"DB Error: {e}")
finally:
    if 'conn' in locals():
        conn.close()
