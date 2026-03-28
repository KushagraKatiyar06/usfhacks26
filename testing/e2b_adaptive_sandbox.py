"""
Adaptive Malware Sandbox — e2b_adaptive_sandbox.py

Reference: e2b_sandbox_test.py (static mock, crashes on unknown Windows APIs)

Strategy:
  1. Run malware in e2b sandbox with current mock
  2. Collect all stdout/stderr
  3. On crash, send error + current mock to Gemini → it generates a JS patch
  4. Append patch to mock, re-run
  5. Loop up to MAX_ITERATIONS or until clean completion
  6. Aggregate behavior graph across all runs
"""

import os
import json
import networkx as nx
import matplotlib.pyplot as plt
import google.generativeai as genai
from pathlib import Path
from dotenv import load_dotenv
from e2b_code_interpreter import Sandbox

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.absolute()
load_dotenv(dotenv_path=SCRIPT_DIR / ".env")

MAX_ITERATIONS = 6          # max mock-patch loops
RUN_TIMEOUT    = 45         # seconds per sandbox run

# ---------------------------------------------------------------------------
# Base Windows mock — choose how bare to start
# ---------------------------------------------------------------------------

# OPTION A: truly empty — Gemini must build everything from scratch
BASE_WINDOWS_MOCK_EMPTY = r"""
console.log('[SYSTEM] Bare sandbox started — no mock loaded.');
"""

# OPTION B: just the catch-all proxy (Gemini prompt tells it patches can reference this)
BASE_WINDOWS_MOCK_CATCHALL_ONLY = r"""
const catchAll = {
    get: function(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === 'string' && prop.length < 100) {
            console.log('[MOCK ATTEMPT] Called: ' + prop);
        }
        return function() { return this; };
    }
};
console.log('[SYSTEM] Bare sandbox started — only catchAll defined.');
"""

# OPTION C: original full mock (reference baseline)
BASE_WINDOWS_MOCK_FULL = r"""
const catchAll = {
    get: function(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === 'string' && prop.length < 100) {
            console.log('[MOCK ATTEMPT] Called: ' + prop);
        }
        return function() { return this; };
    }
};

global.GetObject = function(path) {
    console.log('[MOCK WMI] Querying: ' + path);
    return new Proxy({
        ExecQuery: (query) => {
            console.log('[MOCK WMI] Executed: ' + query);
            return [{
                Name: 'Standard PC',
                VideoProcessor: 'GenuineIntel',
                Manufacturer: 'Dell Inc.'
            }];
        }
    }, catchAll);
};

global.ActiveXObject = function(type) {
    console.log('[MOCK ACTIVEX] Created: ' + type);

    if (type.includes('XMLHTTP') || type.includes('WinHttp')) {
        return new Proxy({
            Open: (method, url) => console.log('[MOCK NET] Connecting to: ' + url),
            Send: (data) => console.log('[MOCK NET] Sending exfiltration data...'),
            Status: 200,
            ResponseText: '{"status":"success","country":"US","org":"Business Network"}'
        }, catchAll);
    }

    if (type.includes('Stream')) {
        return new Proxy({
            Open: () => console.log('[MOCK STREAM] Opened Connection'),
            WriteText: (t) => console.log('[MOCK STREAM] Writing payload chunk'),
            SaveToFile: (p) => console.log('[MOCK ATTEMPT] SaveToFile: ' + p),
            Close: () => {}
        }, catchAll);
    }

    if (type.includes('Shell')) {
        return new Proxy({
            Run: (cmd) => console.log('[MOCK ATTEMPT] Run Command: ' + cmd),
            ExpandEnvironmentStrings: (s) => s.replace('%TEMP%', '/tmp').replace('%PUBLIC%', '/home/user'),
            RegRead: (key) => {
                console.log('[MOCK REG] Reading: ' + key);
                if (key.includes('Foxmail') || key.includes('Aerofox')) return 'C:\\Users\\Public\\Foxmail';
                return "1";
            }
        }, catchAll);
    }

    return new Proxy({
        FileExists: (path) => { console.log('[MOCK FS] Checking: ' + path); return true; },
        GetFolder: (path) => ({ Files: [] }),
        CreateTextFile: (path) => { console.log('[MOCK FS] Creating: ' + path); return { Write: () => {}, Close: () => {} }; },
        DeleteFile: (path) => console.log('[MOCK FS] Self-Deletion Attempt: ' + path),
        createElement: (tag) => { return { appendChild: () => {}, text: "" }; }
    }, catchAll);
};

global.WScript = new Proxy({
    CreateObject: (type) => new ActiveXObject(type),
    Sleep: (ms) => console.log('[MOCK TIME] Skipping sleep: ' + ms + 'ms'),
    ScriptName: '6108674530.js',
    Echo: (m) => console.log('[WSCRIPT] ' + m)
}, catchAll);

global.IMLRHNEGARRR = function() { return ""; };
global.IMLRHNEGARR  = function() { return ""; };

console.log('[SYSTEM] Adaptive Simulation Layer Active.');
"""

# --- Active mock: swap between EMPTY / CATCHALL_ONLY / FULL to test ---
BASE_WINDOWS_MOCK = BASE_WINDOWS_MOCK_CATCHALL_ONLY

# ---------------------------------------------------------------------------
# Claude-powered mock patcher
# ---------------------------------------------------------------------------
def ask_gemini_for_patch(error_output: str, current_mock: str, iteration: int) -> str:
    """
    Given the crash output and the current mock JS, ask Gemini 2.5 Flash to produce
    a minimal JS snippet that patches the gap.  Returns raw JS (no markdown).
    """
    genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
    model = genai.GenerativeModel(
        model_name="gemini-2.5-flash",
        system_instruction=(
            "You are a malware sandbox engineer. "
            "Your job is to keep a Windows API mock running so that a security researcher "
            "can observe malware behaviour without it crashing. "
            "When the sandbox crashes on a missing or broken Windows API, you produce a small "
            "JavaScript patch that adds the missing stub. "
            "Rules:\n"
            "- Output ONLY valid JavaScript, no markdown, no explanations.\n"
            "- The patch is appended to the existing mock file, so you may reference "
            "  globals already defined there (catchAll, ActiveXObject, WScript, etc.).\n"
            "- Every stub must log what it intercepts via console.log with a [MOCK PATCH] prefix.\n"
            "- Return values must be plausible Windows API responses (strings / numbers / proxy objects).\n"
            "- Never throw. Always return something.\n"
            "- Keep the patch minimal — fix only what crashed."
        ),
    )

    prompt = (
        f"=== ITERATION {iteration} CRASH REPORT ===\n"
        f"{error_output.strip()}\n\n"
        f"=== CURRENT MOCK (for context) ===\n"
        f"{current_mock[:3000]}\n\n"
        "Generate the JS patch to prevent this crash and let the malware continue running."
    )

    response = model.generate_content(prompt)
    patch = response.text.strip()

    # Strip accidental markdown fences
    if patch.startswith("```"):
        patch = "\n".join(patch.split("\n")[1:])
    if patch.endswith("```"):
        patch = "\n".join(patch.split("\n")[:-1])
    return patch


# ---------------------------------------------------------------------------
# Single sandbox run
# ---------------------------------------------------------------------------
def run_once(sandbox: Sandbox, mock_js: str, malware_js: str) -> tuple[list, bool, str]:
    """
    Write files, execute, collect events.
    Returns (events, clean_exit, stderr_text).
    """
    events: list[dict] = []
    stderr_lines: list[str] = []

    sandbox.files.write("/home/user/mock.js", mock_js)
    sandbox.files.write("/home/user/malware.js", malware_js)

    try:
        result = sandbox.commands.run(
            "node --require /home/user/mock.js /home/user/malware.js",
            on_stdout=lambda msg: events.append({"type": "STDOUT", "data": msg}),
            on_stderr=lambda msg: (
                events.append({"type": "STDERR", "data": msg}),
                stderr_lines.append(msg),
            ),
            timeout=RUN_TIMEOUT,
        )
        clean = result.exit_code == 0
    except Exception as e:
        # e2b raises on non-zero exit; stderr may come via callback or exception message
        clean = False
        if not stderr_lines:
            # exception message contains the stderr — strip the "Command exited..." prefix
            err_str = str(e)
            stderr_lines.append(err_str)

    stderr_text = "\n".join(stderr_lines)
    return events, clean, stderr_text


# ---------------------------------------------------------------------------
# Main adaptive analysis loop
# ---------------------------------------------------------------------------
def adaptive_analyze(filename: str) -> nx.DiGraph:
    full_path = SCRIPT_DIR / filename
    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        malware_js = f.read()

    G = nx.DiGraph()
    root_node = filename
    G.add_node(root_node, type="PROCESS", color="salmon")

    current_mock = BASE_WINDOWS_MOCK_EMPTY 
    all_events: list[dict] = []
    patches_applied: list[str] = []

    print(f"\n[ADAPTIVE] Starting analysis of {filename}")
    print(f"[ADAPTIVE] Max iterations: {MAX_ITERATIONS}\n")

    try:
        with Sandbox.create() as sandbox:
            for iteration in range(1, MAX_ITERATIONS + 1):
                print(f"--- Iteration {iteration}/{MAX_ITERATIONS} ---")

                # File-system watcher
                def handle_fs(event, it=iteration):
                    node = event.path.split("/")[-1]
                    if node:
                        G.add_node(node, type="FILE", color="skyblue")
                        G.add_edge(root_node, node, action=event.operation)
                    all_events.append({"type": "FILESYSTEM", "data": event.path, "iter": it})

                sandbox.files.on_change = handle_fs
                sandbox.files.watch_dir("/home/user")

                events, clean, stderr_text = run_once(sandbox, current_mock, malware_js)
                all_events.extend(events)

                # Process stdout for graph nodes
                for ev in events:
                    if ev.get("type") == "STDOUT":
                        msg = ev.get("data", "")
                        if any(tag in msg for tag in ["[MOCK", "[WSCRIPT", "[SYSTEM", "[PATCH"]):
                            print(f"  [LOG] {msg.strip()}")
                            detail = msg.split("] ", 1)[-1].strip()
                            if detail and detail not in G:
                                G.add_node(detail, type="ACTION", color="gold")
                                G.add_edge(root_node, detail, action="INTENT")

                if clean:
                    print(f"[ADAPTIVE] Clean exit on iteration {iteration}. Done.\n")
                    break

                # Crash — decide whether to patch or give up
                if not stderr_text.strip():
                    print("[ADAPTIVE] Non-zero exit but no stderr. Stopping.")
                    break

                print(f"[ADAPTIVE] Crash detected on iteration {iteration}.")
                print(f"[ADAPTIVE] Stderr tail:\n  {stderr_text[-500:]}\n")

                if iteration == MAX_ITERATIONS:
                    print("[ADAPTIVE] Max iterations reached. Stopping.")
                    break

                print("[ADAPTIVE] Asking Gemini to patch the mock...")
                patch = ask_gemini_for_patch(stderr_text, current_mock, iteration)
                patches_applied.append(patch)
                current_mock = current_mock + "\n\n// === AUTO-PATCH (iteration " + str(iteration) + ") ===\n" + patch
                print(f"[ADAPTIVE] Patch applied ({len(patch)} chars). Retrying...\n")

    except Exception as e:
        print(f"[ADAPTIVE] Fatal sandbox error: {e}")

    # Summary
    print(f"\n[ADAPTIVE] Summary:")
    print(f"  Patches generated : {len(patches_applied)}")
    print(f"  Total events      : {len(all_events)}")
    print(f"  Graph nodes       : {len(G.nodes)}")
    if patches_applied:
        print("\n[ADAPTIVE] Patches written to: adaptive_patches.js")
        with open(SCRIPT_DIR / "adaptive_patches.js", "w") as pf:
            for i, p in enumerate(patches_applied, 1):
                pf.write(f"// === Patch {i} ===\n{p}\n\n")

    return G


# ---------------------------------------------------------------------------
# Visualization (same style as reference)
# ---------------------------------------------------------------------------
def visualize(G: nx.DiGraph):
    if not G or len(G.nodes) <= 1:
        print("No behavior data collected.")
        return

    plt.figure(figsize=(16, 11))
    pos = nx.spring_layout(G, k=1.5, seed=42)
    node_colors = [G.nodes[n].get("color", "gray") for n in G.nodes()]

    nx.draw(G, pos,
            with_labels=True,
            node_color=node_colors,
            node_size=3500,
            font_size=7,
            font_weight="bold",
            arrows=True,
            edge_color="silver",
            width=1.5)

    edge_labels = nx.get_edge_attributes(G, "action")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

    plt.title("Agent Tesla — Adaptive Behavioral Map (multi-iteration)")
    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    graph = adaptive_analyze("6108674530.JS.malicious")
    visualize(graph)
