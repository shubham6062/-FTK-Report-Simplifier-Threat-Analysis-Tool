"""
report_generator.py - Report Generator Module
Exports investigation findings to PDF, HTML, and TXT formats using ReportLab.
"""

import os
import json
import logging
from datetime import datetime
from io import BytesIO
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not available — PDF export disabled.")


class ReportGenerator:
    """
    Generates investigation reports in PDF, HTML, and TXT formats.
    Includes executive summary, case info, all findings, and recommendations.
    """

    COLORS = {
        'critical': '#8e44ad',
        'high':     '#e74c3c',
        'medium':   '#f39c12',
        'low':      '#2ecc71',
        'header':   '#1a1a2e',
        'accent':   '#16213e',
        'text':     '#2c3e50',
    }

    def __init__(self, parsed_data: dict, analysis_results: dict,
                 risk_results: dict, summary: dict):
        self.data = parsed_data
        self.analysis = analysis_results
        self.risk = risk_results
        self.summary = summary
        self.case_info = parsed_data.get('case_info', {})
        self.generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ─── Public API ───────────────────────────────────────────────────────────

    def generate_pdf(self) -> bytes:
        """Generate a PDF investigation report and return as bytes."""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Run: pip install reportlab")

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
            title=f"FTK Forensic Investigation Report - {self.case_info.get('case_name', 'Unknown')}"
        )

        styles = self._build_styles()
        story = []

        story += self._build_pdf_header(styles)
        story += self._build_pdf_case_info(styles)
        story += self._build_pdf_executive_summary(styles)
        story += self._build_pdf_risk_assessment(styles)
        story += self._build_pdf_findings(styles)
        story += self._build_pdf_keywords(styles)
        story += self._build_pdf_browser_activity(styles)
        story += self._build_pdf_usb_activity(styles)
        story += self._build_pdf_timeline(styles)
        story += self._build_pdf_recommendations(styles)
        story += self._build_pdf_footer(styles)

        doc.build(story)
        return buffer.getvalue()

    def generate_html(self) -> str:
        """Generate an HTML investigation report."""
        risk_level = self.risk.get('threat_level', 'UNKNOWN')
        risk_score = self.risk.get('total_score', 0)
        risk_color = self.risk.get('color', '#999')
        stats = self.analysis.get('summary_stats', {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FTK Forensic Investigation Report</title>
<style>
  :root {{
    --bg: #0f0f1a;
    --surface: #1a1a2e;
    --surface2: #16213e;
    --accent: #0f3460;
    --text: #e0e0e0;
    --muted: #888;
    --critical: #8e44ad;
    --high: #e74c3c;
    --medium: #f39c12;
    --low: #2ecc71;
    --border: #2a2a4a;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  .report-header {{ background: linear-gradient(135deg, var(--surface), var(--accent));
    border-radius: 12px; padding: 2.5rem; margin-bottom: 2rem; border-left: 5px solid {risk_color}; }}
  .report-header h1 {{ font-size: 1.8rem; color: #fff; margin-bottom: 0.5rem; }}
  .report-header .meta {{ color: var(--muted); font-size: 0.9rem; }}
  .risk-badge {{ display: inline-block; background: {risk_color}; color: #fff;
    padding: 0.4rem 1.2rem; border-radius: 20px; font-weight: 700; font-size: 1rem; margin-top: 1rem; }}
  .score-big {{ font-size: 3rem; font-weight: 900; color: {risk_color}; }}
  .section {{ background: var(--surface); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .section h2 {{ font-size: 1.2rem; color: #fff; border-bottom: 1px solid var(--border); padding-bottom: 0.6rem; margin-bottom: 1rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; }}
  .stat-card {{ background: var(--surface2); border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-card .val {{ font-size: 2rem; font-weight: 700; color: #fff; }}
  .stat-card .lbl {{ font-size: 0.8rem; color: var(--muted); margin-top: 0.3rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ background: var(--accent); color: #fff; padding: 0.6rem 1rem; text-align: left; }}
  td {{ padding: 0.5rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:hover td {{ background: var(--surface2); }}
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
  .badge-critical {{ background: var(--critical); color: #fff; }}
  .badge-high {{ background: var(--high); color: #fff; }}
  .badge-medium {{ background: var(--medium); color: #000; }}
  .badge-low {{ background: var(--low); color: #000; }}
  .summary-box {{ background: var(--surface2); border-left: 4px solid {risk_color};
    border-radius: 0 8px 8px 0; padding: 1.2rem; line-height: 1.8; }}
  .rec-item {{ background: var(--surface2); border-radius: 8px; padding: 1rem; margin-bottom: 0.8rem; border-left: 4px solid var(--high); }}
  .rec-item.priority-critical {{ border-color: var(--critical); }}
  .rec-item.priority-medium {{ border-color: var(--medium); }}
  .rec-item.priority-low {{ border-color: var(--low); }}
  .rec-title {{ font-weight: 700; color: #fff; margin-bottom: 0.4rem; }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem;
    border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="report-header">
    <h1>🔍 FTK Forensic Investigation Report</h1>
    <div class="meta">
      Case: <strong>{self.case_info.get('case_name', 'Unknown')}</strong> &nbsp;|&nbsp;
      Investigator: <strong>{self.case_info.get('investigator', 'Unknown')}</strong> &nbsp;|&nbsp;
      Generated: <strong>{self.generated_at}</strong>
    </div>
    <div style="margin-top:1rem;">
      <span class="score-big">{risk_score}</span>
      <span style="color:var(--muted);margin-left:0.5rem;">Risk Score</span>
      <br>
      <span class="risk-badge">{risk_level}</span>
    </div>
  </div>

  <!-- Stats Grid -->
  <div class="section">
    <h2>📊 Investigation Summary</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="val">{stats.get('total_files',0)}</div><div class="lbl">Total Files</div></div>
      <div class="stat-card"><div class="val">{stats.get('suspicious_files',0)}</div><div class="lbl">Suspicious Files</div></div>
      <div class="stat-card"><div class="val">{stats.get('deleted_files',0)}</div><div class="lbl">Deleted Files</div></div>
      <div class="stat-card"><div class="val">{stats.get('hidden_files',0)}</div><div class="lbl">Hidden Files</div></div>
      <div class="stat-card"><div class="val">{stats.get('usb_devices',0)}</div><div class="lbl">USB Devices</div></div>
      <div class="stat-card"><div class="val">{stats.get('total_urls',0)}</div><div class="lbl">URLs Found</div></div>
      <div class="stat-card"><div class="val">{stats.get('unique_keywords',0)}</div><div class="lbl">Keywords Hit</div></div>
      <div class="stat-card"><div class="val">{stats.get('malicious_domains',0)}</div><div class="lbl">Malicious Domains</div></div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>📝 Executive Summary</h2>
    <div class="summary-box">{self.summary.get('executive_summary','Not available.')}</div>
  </div>

  <!-- Technical Summary -->
  <div class="section">
    <h2>🔧 Technical Summary</h2>
    <div class="summary-box">{self.summary.get('technical_summary','Not available.')}</div>
  </div>

  <!-- Risk Breakdown -->
  <div class="section">
    <h2>⚠️ Risk Score Breakdown</h2>
    <table>
      <tr><th>Category</th><th>Count</th><th>Weight</th><th>Points</th></tr>
      {''.join(f'<tr><td>{cat}</td><td>{v["count"]}</td><td>+{v["weight"]}</td><td><strong>{v["points"]}</strong></td></tr>' for cat, v in self.risk.get('breakdown', {}).items())}
    </table>
  </div>

  <!-- Suspicious Files -->
  <div class="section">
    <h2>🚨 Suspicious Files</h2>
    {self._html_file_table(self.data.get('suspicious_files', []))}
  </div>

  <!-- Deleted Files -->
  <div class="section">
    <h2>🗑️ Deleted Files</h2>
    {self._html_file_table(self.data.get('deleted_files', []))}
  </div>

  <!-- Keyword Analysis -->
  <div class="section">
    <h2>🔑 Keyword Analysis</h2>
    <table>
      <tr><th>Keyword</th><th>Count</th><th>Locations</th></tr>
      {''.join(f'<tr><td><code>{h["keyword"]}</code></td><td>{h["count"]}</td><td>{h.get("locations","—")}</td></tr>' for h in self.data.get('keyword_hits', []))}
    </table>
  </div>

  <!-- Browser History -->
  <div class="section">
    <h2>🌐 Browser Activity</h2>
    <table>
      <tr><th>Domain</th><th>URL</th><th>Flag</th></tr>
      {''.join(f'<tr><td>{h["domain"]}</td><td style="font-size:0.8rem;word-break:break-all;">{h["url"][:80]}...</td><td>{"<span class=\'badge badge-high\'>⚠ Suspicious</span>" if h.get("suspicious") else "—"}</td></tr>' for h in self.data.get('browser_history', [])[:20])}
    </table>
  </div>

  <!-- USB Activity -->
  <div class="section">
    <h2>🔌 USB Activity</h2>
    <table>
      <tr><th>Device</th><th>Vendor</th><th>Serial</th><th>Timestamp</th></tr>
      {''.join(f'<tr><td>{u["device_name"]}</td><td>{u["vendor"]}</td><td>{u["serial"]}</td><td>{u["timestamp"]}</td></tr>' for u in self.data.get('usb_activity', []))}
    </table>
  </div>

  <!-- Timeline -->
  <div class="section">
    <h2>📅 Forensic Timeline</h2>
    <table>
      <tr><th>Timestamp</th><th>Event Type</th><th>Description</th></tr>
      {''.join(f'<tr><td style="white-space:nowrap;">{e["timestamp"]}</td><td>{e["event_type"]}</td><td>{e["description"][:100]}</td></tr>' for e in self.data.get('timeline', [])[:30])}
    </table>
  </div>

  <!-- Recommendations -->
  <div class="section">
    <h2>✅ Recommendations</h2>
    {''.join(self._html_rec(r) for r in self.analysis.get('recommendations', []))}
  </div>

  <footer>
    FTK Report Simplifier &amp; Threat Analysis Tool &nbsp;|&nbsp; Generated {self.generated_at} &nbsp;|&nbsp;
    Summary Method: {self.summary.get('method_used','Rule-Based')}
  </footer>
</div>
</body>
</html>"""
        return html

    def generate_txt(self) -> str:
        """Generate a plain-text investigation report."""
        lines = []
        sep = "=" * 70
        thin_sep = "-" * 70

        def h1(title): lines.extend([sep, f"  {title}", sep, ""])
        def h2(title): lines.extend([f"  {title}", thin_sep])
        def nl(): lines.append("")

        # Header
        h1("FTK FORENSIC INVESTIGATION REPORT")
        lines.append(f"  Case Name:    {self.case_info.get('case_name', 'Unknown')}")
        lines.append(f"  Investigator: {self.case_info.get('investigator', 'Unknown')}")
        lines.append(f"  Case Number:  {self.case_info.get('case_number', 'Unknown')}")
        lines.append(f"  Generated:    {self.generated_at}")
        lines.append(f"  Risk Score:   {self.risk.get('total_score', 0)}")
        lines.append(f"  Threat Level: {self.risk.get('threat_level', 'UNKNOWN')}")
        nl()

        # Executive Summary
        h1("EXECUTIVE SUMMARY")
        lines.append(self.summary.get('executive_summary', 'Not available.'))
        nl()

        # Technical Summary
        h1("TECHNICAL SUMMARY")
        lines.append(self.summary.get('technical_summary', 'Not available.'))
        nl()

        # Stats
        h1("INVESTIGATION STATISTICS")
        stats = self.analysis.get('summary_stats', {})
        for k, v in stats.items():
            lines.append(f"  {k.replace('_', ' ').title()}: {v}")
        nl()

        # Risk Breakdown
        h1("RISK SCORE BREAKDOWN")
        for cat, v in self.risk.get('breakdown', {}).items():
            lines.append(f"  {cat}: {v['count']} x {v['weight']} = {v['points']} pts")
        nl()

        # Suspicious Files
        h1("SUSPICIOUS FILES")
        for f in self.data.get('suspicious_files', []):
            lines.append(f"  [{f.get('timestamp','?')}] {f.get('name','Unknown')} | {f.get('size','?')}")
        if not self.data.get('suspicious_files'):
            lines.append("  None detected.")
        nl()

        # Keywords
        h1("KEYWORD ANALYSIS")
        for h in self.data.get('keyword_hits', []):
            lines.append(f"  {h['keyword']}: {h['count']} occurrence(s) @ {h.get('locations','?')}")
        nl()

        # Browser History
        h1("BROWSER ACTIVITY")
        for entry in self.data.get('browser_history', [])[:20]:
            flag = " [SUSPICIOUS]" if entry.get('suspicious') else ""
            lines.append(f"  {entry.get('domain','?')}{flag}")
            lines.append(f"    {entry.get('url','')[:100]}")
        nl()

        # USB
        h1("USB ACTIVITY")
        for u in self.data.get('usb_activity', []):
            lines.append(f"  Device: {u.get('device_name','?')}")
            lines.append(f"    Vendor: {u.get('vendor','?')}  Serial: {u.get('serial','?')}")
            lines.append(f"    Timestamp: {u.get('timestamp','?')}")
        nl()

        # Timeline
        h1("FORENSIC TIMELINE")
        for e in self.data.get('timeline', [])[:30]:
            lines.append(f"  [{e.get('timestamp','?')}] {e.get('event_type','?')}: {e.get('description','')[:80]}")
        nl()

        # Recommendations
        h1("RECOMMENDATIONS")
        for i, r in enumerate(self.analysis.get('recommendations', []), 1):
            lines.append(f"  {i}. [{r.get('priority','?')}] {r.get('action','?')}")
            lines.append(f"     {r.get('detail','')}")
            nl()

        lines.append(sep)
        lines.append(f"  END OF REPORT | Generated: {self.generated_at}")
        lines.append(sep)

        return "\n".join(lines)

    def generate_json(self) -> str:
        """Generate a machine-readable JSON export."""
        export = {
            'report_metadata': {
                'generated_at': self.generated_at,
                'tool': 'FTK Report Simplifier & Threat Analysis Tool',
                'summary_method': self.summary.get('method_used', 'Unknown'),
            },
            'case_info': self.case_info,
            'risk': {
                'score': self.risk.get('total_score'),
                'threat_level': self.risk.get('threat_level'),
                'breakdown': self.risk.get('breakdown'),
            },
            'summary': {
                'executive': self.summary.get('executive_summary'),
                'technical': self.summary.get('technical_summary'),
            },
            'statistics': self.analysis.get('summary_stats'),
            'suspicious_files': self.data.get('suspicious_files', []),
            'deleted_files': self.data.get('deleted_files', []),
            'keyword_hits': self.data.get('keyword_hits', []),
            'usb_activity': self.data.get('usb_activity', []),
            'browser_history': self.data.get('browser_history', [])[:50],
            'timeline': self.data.get('timeline', [])[:50],
            'recommendations': self.analysis.get('recommendations', []),
        }
        return json.dumps(export, indent=2, default=str)

    def generate_csv(self) -> str:
        """Generate CSV export of file listings."""
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Filename', 'Size', 'Timestamp', 'Path', 'Category'])
        for f in self.data.get('file_listings', []):
            name = f.get('name', '')
            ext = os.path.splitext(name)[1].lower() if name else ''
            if ext in {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.jar'}:
                cat = 'Suspicious'
            elif 'recycl' in f.get('path','').lower() or 'deleted' in name.lower():
                cat = 'Deleted'
            else:
                cat = 'Normal'
            writer.writerow([name, f.get('size',''), f.get('timestamp',''), f.get('path',''), cat])
        return output.getvalue()

    # ─── PDF Builders ─────────────────────────────────────────────────────────

    def _build_styles(self):
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            'ReportTitle', parent=styles['Title'],
            fontSize=20, textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=6, leading=24
        ))
        styles.add(ParagraphStyle(
            'SectionHeader', parent=styles['Heading1'],
            fontSize=13, textColor=colors.HexColor('#0f3460'),
            spaceAfter=4, spaceBefore=12,
            borderPad=4
        ))
        styles.add(ParagraphStyle(
            'BodySmall', parent=styles['Normal'],
            fontSize=9, leading=14, textColor=colors.HexColor('#2c3e50')
        ))
        styles.add(ParagraphStyle(
            'SummaryText', parent=styles['Normal'],
            fontSize=10, leading=16, textColor=colors.HexColor('#2c3e50'),
            backColor=colors.HexColor('#f4f6f9'),
            borderPad=8
        ))
        return styles

    def _build_pdf_header(self, styles):
        items = []
        risk_level = self.risk.get('threat_level', 'UNKNOWN')
        risk_score = self.risk.get('total_score', 0)
        items.append(Paragraph("🔍 FTK Forensic Investigation Report", styles['ReportTitle']))
        items.append(Paragraph(
            f"<font color='grey'>Case: <b>{self.case_info.get('case_name','Unknown')}</b> | "
            f"Investigator: <b>{self.case_info.get('investigator','Unknown')}</b> | "
            f"Generated: <b>{self.generated_at}</b></font>",
            styles['BodySmall']
        ))
        risk_color_map = {'LOW': '#2ecc71', 'MEDIUM': '#f39c12', 'HIGH': '#e74c3c', 'CRITICAL': '#8e44ad'}
        rc = risk_color_map.get(risk_level, '#999')
        items.append(Spacer(1, 0.15*inch))
        items.append(Paragraph(
            f"<font color='{rc}'><b>Risk Score: {risk_score} | Threat Level: {risk_level}</b></font>",
            styles['SectionHeader']
        ))
        items.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0f3460')))
        items.append(Spacer(1, 0.2*inch))
        return items

    def _build_pdf_case_info(self, styles):
        items = [Paragraph("Case Information", styles['SectionHeader'])]
        data = [
            ['Case Name', self.case_info.get('case_name', 'Unknown')],
            ['Case Number', self.case_info.get('case_number', 'Unknown')],
            ['Investigator', self.case_info.get('investigator', 'Unknown')],
            ['Date', self.case_info.get('date', 'Unknown')],
        ]
        t = Table(data, colWidths=[2.5*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0,0), (0,-1), colors.white),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (1,0), (-1,-1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        items.append(t)
        items.append(Spacer(1, 0.15*inch))
        return items

    def _build_pdf_executive_summary(self, styles):
        items = [Paragraph("Executive Summary", styles['SectionHeader'])]
        items.append(Paragraph(self.summary.get('executive_summary', 'Not available.'), styles['SummaryText']))
        items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_risk_assessment(self, styles):
        items = [Paragraph("Risk Score Breakdown", styles['SectionHeader'])]
        rows = [['Category', 'Count', 'Weight', 'Points']]
        for cat, v in self.risk.get('breakdown', {}).items():
            rows.append([cat, str(v['count']), f"+{v['weight']}", str(v['points'])])
        rows.append(['TOTAL SCORE', '', '', str(self.risk.get('total_score', 0))])

        t = Table(rows, colWidths=[3.5*inch, 1*inch, 1*inch, 1*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f3460')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.white, colors.HexColor('#f8f9fa')]),
            ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0,-1), (-1,-1), colors.white),
            ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        items.append(t)
        items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_findings(self, styles):
        items = [Paragraph("Suspicious & Deleted Files", styles['SectionHeader'])]
        susp = self.data.get('suspicious_files', [])
        deleted = self.data.get('deleted_files', [])
        combined = [{'name': f['name'], 'category': 'Suspicious', 'ts': f.get('timestamp', '?')} for f in susp]
        combined += [{'name': f['name'], 'category': 'Deleted', 'ts': f.get('timestamp', '?')} for f in deleted]

        if combined:
            rows = [['Filename', 'Category', 'Timestamp']]
            for f in combined[:30]:
                rows.append([f['name'], f['category'], f['ts']])
            t = Table(rows, colWidths=[3.5*inch, 1.5*inch, 1.5*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e74c3c')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fff8f8')]),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            items.append(t)
        else:
            items.append(Paragraph("No suspicious or deleted files detected.", styles['BodySmall']))
        items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_keywords(self, styles):
        items = [Paragraph("Keyword Analysis", styles['SectionHeader'])]
        kw = self.data.get('keyword_hits', [])
        if kw:
            rows = [['Keyword', 'Count', 'Locations']]
            for h in kw:
                rows.append([h['keyword'], str(h['count']), h.get('locations', '?')[:60]])
            t = Table(rows, colWidths=[1.5*inch, 1*inch, 4*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f39c12')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fffdf0')]),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            items.append(t)
        else:
            items.append(Paragraph("No keyword hits found.", styles['BodySmall']))
        items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_browser_activity(self, styles):
        items = [Paragraph("Browser Activity", styles['SectionHeader'])]
        history = self.data.get('browser_history', [])[:15]
        if history:
            rows = [['Domain', 'Suspicious?', 'URL (truncated)']]
            for h in history:
                flag = '⚠ YES' if h.get('suspicious') else 'No'
                rows.append([h.get('domain','?')[:40], flag, h.get('url','?')[:50]])
            t = Table(rows, colWidths=[2*inch, 1*inch, 3.5*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0f4ff')]),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            items.append(t)
        else:
            items.append(Paragraph("No browser history found.", styles['BodySmall']))
        items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_usb_activity(self, styles):
        items = [Paragraph("USB Activity", styles['SectionHeader'])]
        usb = self.data.get('usb_activity', [])
        if usb:
            rows = [['Device Name', 'Vendor', 'Serial', 'Timestamp']]
            for u in usb:
                rows.append([u.get('device_name','?')[:40], u.get('vendor','?'), u.get('serial','?'), u.get('timestamp','?')])
            t = Table(rows, colWidths=[2.5*inch, 1.2*inch, 1.2*inch, 1.6*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#8e44ad')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8f0ff')]),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            items.append(t)
        else:
            items.append(Paragraph("No USB activity detected.", styles['BodySmall']))
        items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_timeline(self, styles):
        items = [Paragraph("Forensic Timeline (first 20 events)", styles['SectionHeader'])]
        timeline = self.data.get('timeline', [])[:20]
        if timeline:
            rows = [['Timestamp', 'Event Type', 'Description']]
            for e in timeline:
                rows.append([e.get('timestamp','?'), e.get('event_type','?'), e.get('description','?')[:60]])
            t = Table(rows, colWidths=[1.8*inch, 1.5*inch, 3.2*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0f0f0')]),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            items.append(t)
        else:
            items.append(Paragraph("No timeline events found.", styles['BodySmall']))
        items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_recommendations(self, styles):
        items = [PageBreak(), Paragraph("Recommendations", styles['SectionHeader'])]
        recs = self.analysis.get('recommendations', [])
        priority_colors = {'CRITICAL': '#8e44ad', 'HIGH': '#e74c3c', 'MEDIUM': '#f39c12', 'LOW': '#2ecc71'}
        for i, rec in enumerate(recs, 1):
            pc = priority_colors.get(rec.get('priority','LOW'), '#999')
            items.append(Paragraph(
                f"<font color='{pc}'><b>{i}. [{rec.get('priority','?')}] {rec.get('action','?')}</b></font>",
                styles['BodySmall']
            ))
            items.append(Paragraph(rec.get('detail', ''), styles['BodySmall']))
            items.append(Spacer(1, 0.1*inch))
        return items

    def _build_pdf_footer(self, styles):
        return [
            HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')),
            Spacer(1, 0.1*inch),
            Paragraph(
                f"<font color='grey'>FTK Report Simplifier &amp; Threat Analysis Tool | "
                f"Generated: {self.generated_at} | Method: {self.summary.get('method_used','Rule-Based')}</font>",
                styles['BodySmall']
            ),
        ]

    # ─── HTML helpers ─────────────────────────────────────────────────────────

    def _html_file_table(self, files: list) -> str:
        if not files:
            return '<p style="color:#888;">None detected.</p>'
        rows = ''.join(
            f'<tr><td>{f.get("name","?")}</td><td>{f.get("size","?")}</td><td>{f.get("timestamp","?")}</td></tr>'
            for f in files[:30]
        )
        return f'<table><tr><th>Filename</th><th>Size</th><th>Timestamp</th></tr>{rows}</table>'

    def _html_rec(self, rec: dict) -> str:
        p = rec.get('priority', 'LOW').lower()
        return (
            f'<div class="rec-item priority-{p}">'
            f'<div class="rec-title">[{rec.get("priority","?")}] {rec.get("action","?")}</div>'
            f'<div>{rec.get("detail","")}</div>'
            f'</div>'
        )
