import json
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()
MODEL = "claude-haiku-4-5"

def call_claude(system_prompt: str, user_message: str) -> dict:
    """Call Claude and return parsed JSON response."""
    response = client.messages.create(
        model=MODEL,
        max_tokens=2000,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}]
    )
    text = response.content[0].text.strip()
    return json.loads(text)

def run_ingestion(file_metadata: dict) -> dict:
    print("Running Ingestion Agent...")
    return call_claude(
        system_prompt="""You are a malware triage specialist.
        Given raw file metadata, structure it cleanly and flag anything suspicious.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "file_name": "string",
            "file_type": "string",
            "file_size_kb": number,
            "sha256": "string",
            "suspicious_flags": ["list of concerns"],
            "confidence": 0.95
        }""",
        user_message=f"Analyze this file metadata: {json.dumps(file_metadata)}"
    )

def run_static_analysis(ingestion_output: dict) -> dict:
    print("Running Static Analysis Agent...")
    return call_claude(
        system_prompt="""You are a malware analyst specializing in static analysis.
        Classify the malware type, explain behavior, identify obfuscation, assess severity.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "malware_type": "string",
            "likely_behavior": "string",
            "obfuscation_techniques": ["list"],
            "severity": 8,
            "iocs": ["list"],
            "confidence": 0.9
        }""",
        user_message=f"Analyze this malware metadata: {json.dumps(ingestion_output)}"
    )

def run_mitre_mapping(ingestion_output: dict) -> dict:
    print("Running MITRE Mapping Agent...")
    return call_claude(
        system_prompt="""You are a MITRE ATT&CK framework specialist.
        Map behaviors to the most specific ATT&CK technique IDs possible.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "techniques": [
                {
                    "id": "T1059.007",
                    "name": "string",
                    "tactic": "string",
                    "reason": "string"
                }
            ],
            "confidence": 0.9
        }""",
        user_message=f"Map these malware behaviors to MITRE ATT&CK: {json.dumps(ingestion_output)}"
    )

def run_remediation(static_output: dict, mitre_output: dict) -> dict:
    print("Running Remediation Agent...")
    return call_claude(
        system_prompt="""You are a cybersecurity incident responder.
        Given malware analysis and MITRE techniques, provide YARA rule, IOCs, containment steps.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "yara_rule": "string",
            "iocs_to_block": ["list"],
            "containment_steps": ["list"],
            "confidence": 0.9,
            "needs_rerun": false
        }""",
        user_message=f"Generate remediation. Static: {json.dumps(static_output)}. MITRE: {json.dumps(mitre_output)}"
    )

def run_report(ingestion: dict, static: dict, mitre: dict, remediation: dict) -> dict:
    print("Running Report Agent...")
    return call_claude(
        system_prompt="""You are a senior threat intelligence analyst.
        Synthesize all findings into a final report.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "executive_summary": "3 sentence summary",
            "risk_score": 85,
            "malware_type": "string",
            "mitre_techniques": [{"id": "string", "name": "string", "tactic": "string"}],
            "iocs": ["list"],
            "yara_rule": "string",
            "action_plan": [{"priority": 1, "action": "string", "urgency": "immediate"}],
            "confidence": 0.9
        }""",
        user_message=f"Generate final report. Ingestion: {json.dumps(ingestion)}. Static: {json.dumps(static)}. MITRE: {json.dumps(mitre)}. Remediation: {json.dumps(remediation)}"
    )

def run_pipeline(file_metadata: dict):
    print("Starting MalwareScope Pipeline...")
    print("=" * 50)

    ingestion = run_ingestion(file_metadata)
    print(f"Ingestion complete")

    # TODO: run static + MITRE in parallel
    static = run_static_analysis(ingestion)
    mitre = run_mitre_mapping(ingestion)

    remediation = run_remediation(static, mitre)
    report = run_report(ingestion, static, mitre, remediation)

    print("Pipeline complete!")
    print(json.dumps(report, indent=2))
    return report

mock_file = {
    "file_name": "6108674530.JS.malicious",
    "file_type": "JavaScript",
    "file_size_kb": 4086,
    "sha256": "abc123placeholder",
    "raw_indicators": ["eval", "unescape", "WScript.Shell", "ActiveXObject", "http://suspicious-domain.ru"]
}

if __name__ == "__main__":
    run_pipeline(mock_file)
