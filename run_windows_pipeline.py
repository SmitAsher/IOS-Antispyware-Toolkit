import subprocess
import os
import glob
from pathlib import Path
import smtplib, ssl
from email.message import EmailMessage
from datetime import datetime
import getpass
import shutil

def step(msg):
    print("\n" + "="*60)
    print(f"🔹 {msg}")

def extract_sysdiagnose():
    SYS_DIR = Path("./sysdiagnosis")
    SYS_DIR.mkdir(exist_ok=True)
    step("Extracting sysdiagnose files from iPhone (Windows)...")
    proc = subprocess.run(
        ["idevicecrashreport.exe", "-e", "-k", str(SYS_DIR)],
        capture_output=True, text=True
    )
    if proc.returncode != 0:
        print("❌ Extraction failed:", proc.stderr)
        exit(1)
    files = sorted(SYS_DIR.glob("sysdiagnose*"), key=os.path.getctime, reverse=True)
    if not files:
        print("❌ No sysdiagnose files extracted.")
        exit(1)
    latest = files[0]
    print(f"👉 Latest sysdiagnose file: {latest}")
    return latest

def unzip_or_untar(file_path, out_dir):
    out_dir.mkdir(exist_ok=True)
    step(f"Extracting {file_path.name}")
    file_str = str(file_path)
    if file_str.endswith(".zip"):
        shutil.unpack_archive(file_str, str(out_dir))
    elif file_str.endswith(".tar") or file_str.endswith(".gz"):
        shutil.unpack_archive(file_str, str(out_dir))
    else:
        print(f"Not an archive. Skipping extraction. Input: {file_path}")
    return out_dir

def run_scan(scan_dir):
    step(f"Running scan on directory: {scan_dir}")
    proc = subprocess.run([
        "python", "scan_indicators.py",
        "--dir", str(scan_dir),
        "--indicators", "./indicators",
        "--report", "results.txt",
        "--summary", "summary_report.txt"
    ])
    if proc.returncode != 0:
        print("❌ scan_indicators.py failed!")
        exit(3)

def mail_results():
    step("Emailing results.txt to client")
    client_email = input("Enter recipient (client) email: ")
    sender_email = input("Enter YOUR (sender) email: ")
    password = getpass.getpass("Enter your email password or app password (for Gmail): ")
    subject = f"iOS Sysdiagnosis Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    body = "Attached: automated sysdiagnosis scan results."
    filename = "results.txt"

    msg = EmailMessage()
    msg['From'] = sender_email
    msg['To'] = client_email
    msg['Subject'] = subject
    msg.set_content(body)
    with open(filename, "rb") as f:
        msg.add_attachment(f.read(), maintype='text', subtype='plain', filename=filename)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.send_message(msg)
    print(f"✅ Results mailed to {client_email}!")

def main():
    latest = extract_sysdiagnose()
    extracted = Path("./extracted_sysdiag")
    if latest.suffix in [".zip", ".tar", ".gz"]:
        unzip_or_untar(latest, extracted)
        scan_dir = extracted
    else:
        scan_dir = latest
    run_scan(scan_dir)
    mail_results()

if __name__ == "__main__":
    main()
