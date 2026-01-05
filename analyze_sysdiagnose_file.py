import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime
import requests

VENV_DIR = Path("venv")
PYTHON = sys.executable
DEPENDENCIES = ["fpdf2", "tqdm", "requests", "email-validator", "PyYAML", "matplotlib"]

def ensure_venv_and_deps():
    if not VENV_DIR.exists():
        print("🔹 Creating Python venv and installing dependencies...")
        subprocess.check_call([PYTHON, "-m", "venv", str(VENV_DIR)])
        pip = str(VENV_DIR / "bin" / "pip")
        subprocess.check_call([pip, "install", "--upgrade", "pip"])
        for dep in DEPENDENCIES:
            subprocess.check_call([pip, "install", dep])
    else:
        pip = str(VENV_DIR / "bin" / "pip")
        for dep in DEPENDENCIES:
            mod = dep.lower().replace("-", "_")
            try:
                __import__(mod)
            except ImportError:
                subprocess.check_call([pip, "install", dep])

def reinvoke_in_venv():
    if sys.prefix != str(VENV_DIR.resolve()):
        py_in_venv = VENV_DIR / "bin" / "python3"
        print(f"🔹 Switching to venv interpreter: {py_in_venv}")
        os.execv(str(py_in_venv), [str(py_in_venv)] + sys.argv)

def step(message):
    print(f"\n{'='*60}\n🔹 {message}")

def find_latest_sysdiagnose(sys_dir):
    patterns = ["**/sysdiagnose*.tar.gz", "**/sysdiagnose*.tgz", "**/sysdiagnose*.tar", "**/sysdiagnose*.zip"]
    candidates = []
    for pat in patterns:
        candidates.extend(sys_dir.glob(pat))
    if not candidates:
        print(f"❌ No sysdiagnose archive found in {sys_dir}.")
        exit(1)
    latest = max(candidates, key=os.path.getctime)
    print(f"👉 Latest sysdiagnose archive: {latest}")
    return latest

def unzip_or_untar(file_path, out_dir):
    out_dir.mkdir(exist_ok=True)
    step(f"Extracting archive: {file_path.name}")
    file_str = str(file_path)
    if file_str.endswith(".zip"):
        out = subprocess.run(["unzip", "-o", file_str, "-d", str(out_dir)])
        if out.returncode != 0:
            print("❌ Failed to unzip.")
            exit(2)
    elif file_str.endswith(".tar") or file_str.endswith(".tar.gz") or file_str.endswith(".tgz") or file_str.endswith(".gz"):
        out = subprocess.run(["tar", "-xf", file_str, "-C", str(out_dir)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if out.returncode != 0:
            print("❌ Failed to untar.")
            exit(2)
    else:
        print(f"⚠️ Not an archive. Skipping extraction. Input: {file_path}")
    return out_dir

def run_scan(scan_dir):
    step(f"Running scan on directory: {scan_dir}")
    py_in_venv = VENV_DIR / "bin" / "python3"
    proc = subprocess.run([
        str(py_in_venv), "scan_indicators.py",
        "--dir", str(scan_dir),
        "--indicators", "./indicators",
        "--report", "results.txt",
        "--summary", "summary_report.txt"
    ])
    if proc.returncode != 0:
        print("❌ scan_indicators.py failed!")
        exit(3)

def parse_findings_from_results(results_path="results.txt"):
    findings = []
    keys = ["indicator", "severity", "remediation", "matched_text", "filepath"]
    try:
        with open(results_path, encoding="utf-8", errors="replace") as f:
            chunk = {k: "" for k in keys}
            for line in f:
                line = line.strip()
                if not line:
                    if any(chunk.values()):
                        findings.append(dict(chunk))
                        chunk = {k: "" for k in keys}
                    continue
                lower = line.lower()
                if "indicator" in lower:
                    chunk["indicator"] = line.split(":", 1)[-1].strip()
                elif "severity" in lower:
                    chunk["severity"] = line.split(":", 1)[-1].strip().capitalize()
                elif "remediation" in lower:
                    chunk["remediation"] = line.split(":", 1)[-1].strip()
                elif "evidence" in lower:
                    chunk["matched_text"] = line.split(":", 1)[-1].strip()
                elif "file" in lower:
                    chunk["filepath"] = line.split(":", 1)[-1].strip()
            if any(chunk.values()):
                findings.append(chunk)
    except Exception as e:
        print(f"ERROR PARSING FINDINGS: {e}")
    for f in findings:
        for k in keys:
            if not f.get(k):
                f[k] = "Unknown"
    return findings

def generate_full_report_with_gemini(findings, scan_date, scan_path):
    def format_findings(findings):
        out = []
        for idx, f in enumerate(findings, 1):
            out.append(
                f"{idx}. Indicator: {f.get('indicator','Unknown')} | Severity: {f.get('severity','Unknown')}\n"
                f"   Remediation: {f.get('remediation','Unknown')}\n"
                f"   Evidence: {f.get('matched_text','Unknown')}\n"
                f"   File: {f.get('filepath','Unknown')}\n"
            )
        return "\n".join(out)

    api_key = os.environ.get("GEMINI_API_KEY")
    api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key
    }

    findings_block = format_findings(findings)
    prompt = (
        f"You are a top-tier cybersecurity analyst tasked to write a boardroom-ready, CISO-facing iOS sysdiagnose report. "
        f"This scan occurred on {scan_date.strftime('%B %d, %Y')}. "
        f"Filename: {os.path.basename(scan_path)}. "
        f"Below are all detected findings:\n\n{findings_block}\n\n"
        "Write a report with:\n"
        "- Executive brief and high-level summary\n"
        "- Full risk analytics, metrics, and threat distribution\n"
        "- Indicator table (top 10 threats, summary style)\n"
        "- Strategic impact and synthesis\n"
        "- Response actions and recommendations\n"
        "Make the report formal, professional, and suitable for direct board/CISO and SOC presentation. Use paragraph sections, not bullet lists."
    )

    payload = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ]
    }
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
        result = response.json()
        gemini_text = ""
        if "candidates" in result and result["candidates"]:
            gemini_text = result["candidates"][0]["content"]["parts"][0].get("text", "")
        else:
            gemini_text = result.get("content", {}).get("parts", [{}])[0].get("text", "")
    except Exception as e:
        gemini_text = f"Gemini full report generation failed: {e}"
    return gemini_text

def main():
    ensure_venv_and_deps()
    reinvoke_in_venv()
    sys_dir = Path("sysdiagnosis_drop")
    sys_dir.mkdir(exist_ok=True)
    print("🔹 Copy your .tar.gz sysdiagnose file into ./sysdiagnosis_drop/, then re-run if prompted.")
    latest = find_latest_sysdiagnose(sys_dir)
    extracted = Path("extracted_sysdiag")
    unzip_or_untar(latest, extracted)
    run_scan(extracted)

    from elite_report_generator import generate_elite_pdf_report
    findings = parse_findings_from_results("results.txt")
    scan_date = datetime.now()
    gemini_report = generate_full_report_with_gemini(findings, scan_date, str(latest))
    generate_elite_pdf_report(findings, "security_report.pdf", logo_path=None, scan_path=str(latest), ai_full_report=gemini_report)
    print("\n🎉 Elite sysdiagnose analysis complete. PDF saved as security_report.pdf.")

if __name__ == "__main__":
    main()
