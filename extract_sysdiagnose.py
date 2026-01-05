import subprocess, glob, os
from pathlib import Path

SYS_DIR = Path("./sysdiagnosis")
SYS_DIR.mkdir(exist_ok=True)

print("🛡️ Extracting sysdiagnose files from connected iPhone...")
proc = subprocess.run(
    ["idevicecrashreport", "-e", "-k", str(SYS_DIR)],
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
with open("latest_sysdiagnose.txt", "w") as f:
    f.write(str(latest.resolve()))
