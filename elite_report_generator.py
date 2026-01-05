from fpdf import FPDF
from datetime import datetime
import os
import matplotlib.pyplot as plt

class ElitePDFReport(FPDF):
    NAVY = (15, 32, 75)
    CRIMSON = (153, 27, 27)
    AMBER = (180, 83, 9)
    FOREST = (20, 83, 45)
    CHARCOAL = (31, 41, 55)
    STEEL = (148, 163, 184)
    GOLD = (161, 98, 7)
    PLATINUM = (248, 250, 252)

    def __init__(self, org_name="DeepCytes", logo_path=None):
        super().__init__(format='A4')
        self.org_name = org_name
        self.logo_path = logo_path
        self.set_auto_page_break(auto=True, margin=28)
        self.set_margins(22, 22, 22)
        font_path = "DejaVuSans.ttf"
        if not os.path.isfile(font_path):
            font_path = "/home/kali/Ios_sysdiagnoosis/DejaVuSans.ttf"
        if not os.path.isfile(font_path):
            raise FileNotFoundError(f"Font file not found: {font_path}")
        self.add_font("DejaVu", '', font_path, uni=True)
        self.add_font("DejaVu", 'B', font_path, uni=True)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_draw_color(220, 225, 235)
        self.set_line_width(0.3)
        self.line(18, 18, 192, 18)
        x_start = 22
        if self.logo_path and os.path.exists(self.logo_path):
            try:
                self.image(self.logo_path, x=22, y=20, h=8)
                x_start = 35
            except:
                x_start = 22
        self.set_xy(x_start, 21)
        self.set_font('DejaVu', 'B', 9)
        self.set_text_color(*self.CHARCOAL)
        self.cell(0, 4, self.org_name.upper())
        self.set_xy(x_start, 25)
        self.set_font('DejaVu', '', 7)
        self.set_text_color(*self.STEEL)
        self.cell(0, 3, 'Threat Intelligence & Security Analysis')
        self.ln(16)

    def footer(self):
        self.set_y(-18)
        self.set_draw_color(220, 225, 235)
        self.set_line_width(0.3)
        self.line(22, self.get_y(), 188, self.get_y())
        self.ln(3)
        self.set_font('DejaVu', '', 7)
        self.set_text_color(*self.STEEL)
        self.cell(84, 4, 'CONFIDENTIAL & PROPRIETARY')
        self.cell(84, 4, f'Page {self.page_no()}', align='R')

    def add_elite_cover(self, findings_count, scan_date, scan_path):
        self.add_page()
        self.set_fill_color(*self.NAVY)
        self.rect(0, 0, 210, 297, 'F')
        if self.logo_path and os.path.exists(self.logo_path):
            self.image(self.logo_path, x=70, y=38, w=70)
        self.set_y(115)
        self.set_font('DejaVu', 'B', 28)
        self.set_text_color(255, 255, 255)
        self.cell(0, 18, "THREAT INTELLIGENCE REPORT", ln=1, align='C')
        self.set_font('DejaVu', '', 16)
        self.set_text_color(200, 215, 250)
        self.ln(3)
        self.cell(0, 11, "iOS Security Analysis & Risk Assessment", ln=1, align='C')
        self.set_y(175)
        self.set_font('DejaVu', '', 12)
        self.set_text_color(248, 250, 252)
        self.cell(0, 8, f"Security Findings: {findings_count}", ln=1, align='C')
        self.cell(0, 8, f"Scan Date: {scan_date.strftime('%B %d, %Y')}", ln=1, align='C')
        if scan_path:
            self.cell(0, 8, f"Target: {os.path.basename(scan_path)}", ln=1, align='C')
        self.set_y(277)
        self.set_font('DejaVu', '', 9)
        self.set_text_color(200, 210, 230)
        self.cell(0, 5, f"(C) {datetime.now().year} DeepCytes. All Rights Reserved.", align='C')

    def _elite_section(self, title, subtitle=''):
        y = self.get_y()
        for i in range(4):
            self.set_fill_color(*tuple(int(c * (1 - i * 0.15)) for c in self.NAVY))
            self.rect(22 + i, y, 1, 12, 'F')
        self.set_xy(30, y + 2)
        self.set_font('DejaVu', 'B', 16)
        self.set_text_color(*self.NAVY)
        self.cell(0, 6, title)
        if subtitle:
            self.set_xy(30, y + 8)
            self.set_font('DejaVu', '', 9)
            self.set_text_color(*self.STEEL)
            self.cell(0, 4, subtitle)
        self.ln(16)

    def add_gemini_full_report(self, ai_full_report):
        self.add_page()
        self._elite_section('Gemini AI - Full Executive Report', 'Generated CISO/boardroom summary')
        self.set_font("DejaVu", '', 10)
        self.set_text_color(*self.CHARCOAL)
        self.multi_cell(0, 7, ai_full_report or "No Gemini output available.")
        self.ln(15)

    # (Other analytics/threat intelligence methods remain unchanged)

def generate_elite_pdf_report(findings, filename, logo_path=None, scan_path="", ai_full_report=None):
    print(f"\n{'='*70}")
    print(f"  GENERATING ELITE THREAT INTELLIGENCE REPORT")
    print(f"{'='*70}\n")
    try:
        pdf = ElitePDFReport(
            org_name="DeepCytes",
            logo_path=logo_path
        )
        pdf.alias_nb_pages()
        scan_date = datetime.now()
        print("  [1/5] Crafting elite cover page...")

        pdf.add_elite_cover(len(findings), scan_date, scan_path)

        if ai_full_report:
            print("  [2/5] Inserting Gemini executive report section...")
            pdf.add_gemini_full_report(ai_full_report)

        # The rest of your analytics, detailed findings, etc:
        print("  [3/5] Generating threat analytics...")
        if findings:
            pdf.add_threat_analytics(findings)
        print("  [4/5] Compiling threat intelligence...")
        pdf.add_threat_intelligence(findings)
        print("  [5/5] Finalizing response strategy...")
        if findings:
            pdf.add_response_strategy(findings)

        pdf.output(filename)
        print(f"\n{'='*70}")
        print(f"  ELITE REPORT GENERATED SUCCESSFULLY")
        print(f"{'='*70}")
        print(f"  File: {filename}")
        print(f"  Pages: {pdf.page_no()}")
        print(f"  Quality: Board-room ready")
        print(f"  AI Enhanced: {'Yes' if ai_full_report else 'N/A'}")
        print(f"  Status: Production-grade")
        print(f"{'='*70}\n")
    except Exception as e:
        print(f"\n  ERROR: PDF generation failed")
        print(f"  {str(e)}\n")
        import traceback
        traceback.print_exc()
