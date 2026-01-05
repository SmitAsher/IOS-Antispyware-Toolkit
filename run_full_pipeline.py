import subprocess
import os
import sys
import shutil
from pathlib import Path
from datetime import datetime

VENV_DIR = Path("venv")
PYTHON = sys.executable
DEPENDENCIES = ["fpdf2", "tqdm", "requests", "email-validator", "PyYAML"]
FONT_FILE = "DejaVuSans.ttf"
FONT_URL = "https://github.com/dejavu-fonts/dejavu-fonts/raw/version_2_37/ttf/DejaVuSans.ttf"

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
    if not Path(FONT_FILE).exists():
        print("🔹 Downloading DejaVuSans.ttf for PDF Unicode support...")
        subprocess.check_call(["wget", "-O", FONT_FILE, FONT_URL])
    if subprocess.run(["which", "ifuse"], capture_output=True).returncode != 0:
        print("🔹 Installing ifuse with apt...")
        subprocess.check_call(["sudo", "apt", "install", "-y", "ifuse"])

def reinvoke_in_venv():
    if sys.prefix != str(VENV_DIR.resolve()):
        py_in_venv = VENV_DIR / "bin" / "python3"
        print(f"🔹 Switching to venv interpreter: {py_in_venv}")
        os.execv(str(py_in_venv), [str(py_in_venv)] + sys.argv)

def step(message):
    print(f"\n{'='*60}\n🔹 {message}")

def wait_for_device_trusted():
    import time
    step("Waiting for iPhone connection and trust prompt acceptance...")
    while True:
        proc = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True)
        udids = proc.stdout.strip().split("\n")
        udids = [u for u in udids if u and len(u) > 16]
        if udids:
            print(f"✅ iPhone detected! UDID(s): {udids}")
            return udids[0]
        print("⚠️ Connect & unlock iPhone, and tap 'Trust'. Retrying in 3s...")
        time.sleep(3)

def find_latest_sysdiagnose(sys_dir=Path("sysdiagnosis")):
    patterns = ["**/sysdiagnose*.tar.gz", "**/sysdiagnose*.tgz", "**/sysdiagnose*.tar", "**/sysdiagnose*.zip"]
    candidates = []
    for pat in patterns:
        candidates.extend(sys_dir.glob(pat))
    if not candidates:
        print("❌ No sysdiagnose archive found in any subfolder.")
        return None
    latest = max(candidates, key=os.path.getctime)
    print(f"👉 Latest sysdiagnose archive: {latest}")
    return latest

def extract_sysdiagnose():
    SYS_DIR = Path("sysdiagnosis")
    SYS_DIR.mkdir(exist_ok=True)
    step("Extracting sysdiagnose files from iPhone (using idevicecrashreport)...")
    proc = subprocess.run(
        ["idevicecrashreport", "-e", "-k", str(SYS_DIR)],
        capture_output=True, text=True
    )
    if proc.returncode != 0:
        print("❌ Extraction failed:", proc.stderr)
        exit(1)
    latest = find_latest_sysdiagnose(SYS_DIR)
    if latest is None:
        exit(1)
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

def copy_report_to_iphone(pdf_path, start_time):
    mount_dir = Path.home() / "iphone_mount"
    mount_dir.mkdir(exist_ok=True)
    print(f"🔹 Mounting iPhone filesystem with ifuse...")
    subprocess.run(["fusermount", "-u", str(mount_dir)], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    result = subprocess.run(["ifuse", str(mount_dir)])
    if result.returncode != 0:
        print(f"❌ Failed to mount iPhone with ifuse. Is the device unlocked and trusted?")
        return
    books_dir = mount_dir / "Books"
    books_dir.mkdir(exist_ok=True)
    date_str = start_time.strftime("%Y%m%d_%H%M%S")
    new_name = f"{date_str}_report.pdf"
    shutil.copyfile(pdf_path, books_dir / new_name)
    print(f"✅ PDF copied to iPhone Books: {books_dir / new_name}")
    subprocess.run(["fusermount", "-u", str(mount_dir)])

# Stub result formatting—replace with actual parsers:
def parse_findings_from_results():
    return [
        {"indicator": "Zero_Click_Exploit_Detection", "severity": "CRITICAL", "file": "malware.txt", "evidence": "Proof-of-concept exploit found", "action": "Audit device, patch immediately"},
        {"indicator": "App_Masquerading", "severity": "HIGH", "file": "ps.txt", "evidence": "Suspicious Safari.bundle", "action": "Review app signature, verify source"}
    ]
def summarize_findings(findings): return "Dynamic critical findings. See detailed section."
def generate_immediate_actions(findings): return ["Isolate compromised device", "Notify security teams"]
def generate_longterm_actions(findings): return ["Review endpoint security", "Plan periodic audits"]
def get_escalation_contacts(): return ["CISO Hotline", "Apple Security Response"]

def main():
    ensure_venv_and_deps()
    reinvoke_in_venv()

    start_time = datetime.now()
    udid = wait_for_device_trusted()
    latest = extract_sysdiagnose()
    extracted = Path("extracted_sysdiag")
    unzip_or_untar(latest, extracted)
    run_scan(extracted)

    findings = parse_findings_from_results()
    date = datetime.now().strftime('%B %d, %Y')
    ai_version = "2.1"
    target = udid or "Unknown"
    strategic_text = summarize_findings(findings)
    immediate_steps = generate_immediate_actions(findings)
    strategic_steps = generate_longterm_actions(findings)
    contacts = get_escalation_contacts()

    # Import and call report generator
    from report_generator import create_report
    create_report(
        findings, date, ai_version, target,
        strategic_text, immediate_steps, strategic_steps, contacts
    )

    copy_report_to_iphone("security_report.pdf", start_time)
    print("\n🎉 Pipeline complete. Report saved locally and on the iPhone (Books folder).")

if __name__ == "__main__":
    main()
