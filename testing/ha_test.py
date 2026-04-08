"""Quick Hybrid Analysis API diagnostic — run with: python ha_test.py"""
import os, hashlib, requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
print(f"API key loaded: {'YES (' + api_key[:8] + '...)' if api_key else 'NO — check .env'}")
print(f"Auth level: restricted (level 1) — submissions NOT available on free tier\n")

BASE = "https://www.hybrid-analysis.com/api/v2"
hdrs = {"api-key": api_key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}

# Compute REAL sha256 from the actual file
file_path = Path(__file__).parent / "samples" / "6108674530.JS.malicious"
if not file_path.exists():
    print(f"ERROR: {file_path} not found")
    exit(1)
SHA = hashlib.sha256(file_path.read_bytes()).hexdigest()
print(f"Real SHA256: {SHA}\n")

tests = [
    ("POST /search/hash — params= (URL query string)",
     lambda: requests.post(f"{BASE}/search/hash", headers=hdrs,
                           params={"hash": SHA}, timeout=10)),

    ("GET  /overview/{sha256} (real hash)",
     lambda: requests.get(f"{BASE}/overview/{SHA}", headers=hdrs, timeout=10)),

    ("GET  /report/{sha256}/summary (real hash — might work for known malware)",
     lambda: requests.get(f"{BASE}/report/{SHA}/summary", headers=hdrs, timeout=10)),

    ("GET  /report/{sha256}/state",
     lambda: requests.get(f"{BASE}/report/{SHA}/state", headers=hdrs, timeout=10)),
]

for name, fn in tests:
    try:
        r = fn()
        body = r.text[:500]
        print(f"[{r.status_code}] {name}")
        print(f"    {body}\n")
    except Exception as e:
        print(f"[ERR] {name}\n    {e}\n")
