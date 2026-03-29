import sys
import os
import json
import tempfile
import shutil

# Allow importing analyze.py from sandbox/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sandbox'))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import anthropic
from dotenv import load_dotenv

# Load backend .env first, then fall back to sandbox .env
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'sandbox', '.env'))

try:
    from analyze import analyze_js
except ImportError as e:
    print(f"Warning: could not import analyze_js: {e}")
    analyze_js = None

app = FastAPI(title="UseProtechtion Malware Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def call_claude_report(file_meta: dict) -> dict:
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2000,
        system="""You are a senior malware analyst. Given static analysis results of a suspicious file, generate a concise threat report.
Output valid JSON only. No markdown fences, no explanation — just the raw JSON object.
Format:
{
  "malware_type": "string (e.g. RANSOMWARE, DROPPER, LOADER, INFOSTEALER, RAT, DOWNLOADER, BACKDOOR)",
  "risk_score": integer (0-100),
  "classification_confidence": integer (0-100),
  "behavior_confidence": integer (0-100),
  "findings": [
    {"type": "critical", "label": "CRITICAL", "text": "short finding"},
    {"type": "warn", "label": "WARNING", "text": "short finding"},
    {"type": "ok", "label": "INFO", "text": "short finding"}
  ],
  "mitigations": ["① first step", "② second step", "③ third step"],
  "reasoning": "2-3 sentence technical explanation of the threat, observed kill chain, and risk assessment"
}""",
        messages=[{
            "role": "user",
            "content": f"Generate a threat report for this malware static analysis result:\n{json.dumps(file_meta, indent=2)}"
        }]
    )

    text = response.content[0].text.strip()
    # Strip markdown code fences if model adds them
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

    return json.loads(text)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if analyze_js is None:
        raise HTTPException(status_code=500, detail="Static analysis module not available")

    # Save uploaded file to a temp path
    suffix = f"_{file.filename}" if file.filename else ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        # Run static analysis
        static_result = analyze_js(tmp_path)

        # Build compact metadata for Claude
        file_meta = {
            "file_name": file.filename,
            "file_size_kb": os.path.getsize(tmp_path) // 1024,
            "entropy": static_result.get("entropy"),
            "is_obfuscated": static_result.get("is_obfuscated"),
            "threat_level": static_result.get("threat_level"),
            "behaviors": static_result.get("behaviors", []),
            "mitre_techniques": static_result.get("mitre_techniques", []),
            "dangerous_functions": static_result.get("dangerous_functions", []),
            "urls_found": static_result.get("urls_found", [])[:5],
            "ips_found": static_result.get("ips_found", [])[:5],
            "registry_keys": static_result.get("registry_keys", [])[:5],
            "dropped_files": static_result.get("dropped_files", [])[:5],
            "possible_aes_keys_count": len(static_result.get("possible_aes_keys", [])),
            "base64_blobs_found": static_result.get("base64_blobs_found", 0),
        }

        ai_report = call_claude_report(file_meta)

        return {
            "static": static_result,
            "report": ai_report,
        }

    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"AI report parse error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        os.unlink(tmp_path)
