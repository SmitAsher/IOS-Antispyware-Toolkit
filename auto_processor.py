#!/usr/bin/env python3
"""
iOS Sysdiagnosis Auto-Processor
Integrates with your existing scan_indicators.py package
"""

import os
import sys
import time
import glob
import shutil
import zipfile
import tarfile
import subprocess
import json
from pathlib import Path
from datetime import datetime

class iOSAntiSpywareAutoProcessor:
    def __init__(self):
        self.base_dir = Path.cwd()
        self.watch_dir = self.base_dir / "sysdiagnosis_drop"
        self.extract_dir = self.base_dir / "extracted_sysdiag"
        self.processed_dir = self.base_dir / "processed"
        self.results_dir = self.base_dir / "results"
        self.indicators_dir = self.base_dir / "indicators"
        
        # Your existing files
        self.scan_script = self.base_dir / "scan_indicators.py"
        self.config_file = self.base_dir / "config-yaml"
        
        # Create all directories
        for dir_path in [self.watch_dir, self.extract_dir, self.processed_dir, 
                        self.results_dir, self.indicators_dir]:
            dir_path.mkdir(exist_ok=True)
    
    def print_banner(self):
        print("=" * 70)
        print("🛡️  iOS AntiSpyware Auto-Processor v2.0")
        print("    Based on your DeepCytes scan_indicators.py package")
        print("=" * 70)
        print(f"📱 iPhone sysdiagnosis generation:")
        print("   1. Volume Up + Volume Down + Power (hold 1-2 seconds)")
        print("   2. Wait for haptic feedback")
        print("   3. Settings > Privacy > Analytics > Analytics Data")
        print("   4. Find 'sysdiagnose' file and share it")
        print(f"   5. Drop file in: {self.watch_dir}")
        print("")
        print(f"📊 Auto-processing with:")
        print(f"   ✅ Your advanced scan_indicators.py")
        print(f"   ✅ Multi-threaded analysis")
        print(f"   ✅ Advanced behavioral detection")
        print(f"   ✅ PDF + JSON + HTML reports")
        print("=" * 70)
        print("🔄 Watching for new files... (Ctrl+C to stop)")
        print("")
    
    def setup_sample_indicators(self):
        """Create sample indicator files if indicators directory is empty"""
        if not any(self.indicators_dir.glob("*.json")):
            print("📄 Creating sample indicator files...")
            
            # Sample malware indicators
            malware_indicators = {
                "name": "iOS_Malware_Signatures",
                "description": "Common iOS malware and spyware signatures",
                "patterns": [
                    "cydia://",
                    "substrate.*hook",
                    "MobileSubstrate.*dylib",
                    "jailbreak.*detect",
                    "suspicious.*payload",
                    "remote.*access.*trojan",
                    "keylogger",
                    "screen.*capture.*unauthorized"
                ],
                "severity": "High",
                "attribution": {
                    "source": "DeepCytes Research",
                    "author": "iOS Security Team",
                    "date_created": "2025-10-01"
                }
            }
            
            # Network indicators
            network_indicators = {
                "name": "Suspicious_Network_Activity",
                "description": "Indicators of malicious network communications",
                "patterns": [
                    "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d{4,5}\\b",
                    "tor.*proxy",
                    "vpn.*unauthorized",
                    "dns.*hijack",
                    "c2.*server",
                    "command.*control",
                    "exfiltration.*data"
                ],
                "severity": "Medium",
                "attribution": {
                    "source": "Network Security Analysis",
                    "author": "DeepCytes",
                    "date_created": "2025-10-01"
                }
            }
            
            # App masquerading
            app_masq_indicators = {
                "name": "App_Masquerading_Detection",
                "description": "Detects apps pretending to be legitimate applications",
                "patterns": [
                    "\\.app\\.app",
                    "Settings.*fake",
                    "Calculator.*spy",
                    "Photos.*hidden",
                    "com\\.apple\\.fake",
                    "[^\\x00-\\x7F].*\\.app"
                ],
                "severity": "High", 
                "attribution": {
                    "source": "App Analysis Framework",
                    "author": "DeepCytes Anti-Spyware",
                    "date_created": "2025-10-01"
                }
            }
            
            # Save indicator files
            indicators = [
                ("malware_signatures.json", malware_indicators),
                ("network_indicators.json", network_indicators),
                ("app_masquerading.json", app_masq_indicators)
            ]
            
            for filename, data in indicators:
                with open(self.indicators_dir / filename, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"   ✅ Created {filename}")
            
            print(f"📁 {len(indicators)} indicator files ready in {self.indicators_dir}")
    
    def extract_archive(self, file_path):
        """Extract sysdiagnosis archive"""
        timestamp = int(time.time())
        extract_path = self.extract_dir / f"sysdiag_{timestamp}"
        extract_path.mkdir(exist_ok=True)
        
        print(f"📦 Extracting {file_path.name}...")
        
        try:
            if file_path.suffix.lower() == '.zip':
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
            elif file_path.suffix.lower() in ['.tar', '.gz', '.tgz']:
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_path)
            else:
                # Try zip first, then tar
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_path)
                except:
                    with tarfile.open(file_path, 'r:*') as tar_ref:
                        tar_ref.extractall(extract_path)
            
            print(f"✅ Extracted to: {extract_path}")
            return extract_path
            
        except Exception as e:
            print(f"❌ Extraction failed: {e}")
            return None
    
    def run_analysis(self, data_dir):
        """Run your scan_indicators.py with full options"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Output files
        results_file = self.results_dir / f"results_{timestamp}.txt"
        summary_file = self.results_dir / f"summary_{timestamp}.txt"
        json_file = self.results_dir / f"results_{timestamp}.json"
        html_file = self.results_dir / f"report_{timestamp}.html"
        pdf_file = self.results_dir / f"security_report_{timestamp}.pdf"
        
        # Build command using your existing script's full capabilities
        cmd = [
            sys.executable, str(self.scan_script),
            "--dir", str(data_dir),
            "--indicators", str(self.indicators_dir),
            "--report", str(results_file),
            "--summary", str(summary_file),
            "--export-json", str(json_file),
            "--export-html", str(html_file),
            "--pdf-report", str(pdf_file),
            "--threads", "12",  # From your config
            "--quiet"  # Reduce noise
        ]
        
        print(f"🚀 Running advanced analysis...")
        print(f"   📊 Results: {results_file.name}")
        print(f"   📋 Summary: {summary_file.name}")
        print(f"   📄 JSON: {json_file.name}")
        print(f"   🌐 HTML: {html_file.name}")
        print(f"   📑 PDF: {pdf_file.name}")
        print()
        
        try:
            # Run the analysis
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                print("✅ Analysis completed successfully!")
                
                # Show summary if available
                if summary_file.exists():
                    print("\n📋 SCAN SUMMARY:")
                    print("-" * 50)
                    try:
                        summary_text = summary_file.read_text(encoding='utf-8')
                        print(summary_text)
                    except:
                        print("Could not read summary file")
                    print("-" * 50)
                
                # Show file sizes
                print("\n📊 Generated Reports:")
                for report_file in [results_file, summary_file, json_file, html_file, pdf_file]:
                    if report_file.exists():
                        size_kb = report_file.stat().st_size / 1024
                        print(f"   {report_file.name}: {size_kb:.1f} KB")
                
                return True
                
            else:
                print(f"❌ Analysis failed with return code: {result.returncode}")
                if result.stderr:
                    print("Error:", result.stderr[:500])
                return False
                
        except subprocess.TimeoutExpired:
            print("⏰ Analysis timed out after 10 minutes")
            return False
        except Exception as e:
            print(f"❌ Failed to run analysis: {e}")
            return False
    
    def move_to_processed(self, file_path):
        """Move processed file to processed directory"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        processed_path = self.processed_dir / f"{timestamp}_{file_path.name}"
        shutil.move(str(file_path), str(processed_path))
        print(f"📦 Archived: {processed_path.name}")
    
    def validate_setup(self):
        """Check if all required files exist"""
        print("🔍 Validating setup...")
        
        required_files = [self.scan_script]
        missing_files = [f for f in required_files if not f.exists()]
        
        if missing_files:
            print(f"❌ Missing required files:")
            for f in missing_files:
                print(f"   - {f}")
            return False
        
        # Check Python dependencies
        try:
            import concurrent.futures
            import tqdm
            print("✅ Python dependencies OK")
        except ImportError as e:
            print(f"⚠️  Missing Python dependency: {e}")
            print("   Try: pip install tqdm")
        
        print("✅ Setup validation complete")
        return True
    
    def watch_and_process(self):
        """Main loop - watch for files and process them"""
        self.print_banner()
        
        if not self.validate_setup():
            print("❌ Setup validation failed. Please fix issues above.")
            return
        
        self.setup_sample_indicators()
        
        processed_files = set()
        
        print(f"👀 Watching {self.watch_dir} for sysdiagnosis files...")
        print()
        
        while True:
            try:
                # Look for sysdiagnosis files
                patterns = [
                    "sysdiagnose*",
                    "*.zip", 
                    "*.tar*",
                    "*.tgz"
                ]
                
                new_files = []
                for pattern in patterns:
                    new_files.extend(self.watch_dir.glob(pattern))
                
                # Filter out processed files
                new_files = [f for f in new_files if f not in processed_files and f.is_file()]
                
                if new_files:
                    for file_path in new_files:
                        print(f"\n🎯 New file detected: {file_path.name}")
                        print(f"📏 Size: {file_path.stat().st_size / 1024 / 1024:.1f} MB")
                        print(f"⏰ Time: {datetime.now().strftime('%H:%M:%S')}")
                        
                        # Extract
                        extract_path = self.extract_archive(file_path)
                        
                        if extract_path:
                            # Run analysis
                            success = self.run_analysis(extract_path)
                            
                            if success:
                                # Move to processed
                                self.move_to_processed(file_path)
                                processed_files.add(file_path)
                                
                                print("\n" + "="*70)
                                print("✨ PROCESSING COMPLETE!")
                                print("   Drop another file to continue analysis...")
                                print("="*70)
                            else:
                                print("❌ Analysis failed - file left in drop folder")
                        else:
                            print("❌ Extraction failed - file left in drop folder")
                
                # Wait before checking again
                time.sleep(2)
                
            except KeyboardInterrupt:
                print("\n\n🛑 Stopping auto-processor...")
                print(f"📁 Results saved in: {self.results_dir}")
                print("👋 Thank you for using DeepCytes iOS AntiSpyware!")
                break
            except Exception as e:
                print(f"❌ Unexpected error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    processor = iOSAntiSpywareAutoProcessor()
    processor.watch_and_process()
