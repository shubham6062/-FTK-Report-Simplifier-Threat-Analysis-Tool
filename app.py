"""
app.py - FTK Report Simplifier & Threat Analysis Tool
Main Streamlit application entry point.

Run with:
    streamlit run app.py
"""

import os
import io
import logging
import json
import hashlib
from datetime import datetime
from pathlib import Path

import streamlit as st
import pandas as pd

from parser import FTKReportParser
from analyzer import ForensicAnalyzer
from risk_engine import RiskEngine
from ai_summary import AISummaryGenerator
from report_generator import ReportGenerator
from dashboard import DashboardCharts

# ─── Configuration ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

UPLOAD_DIR = Path("uploads")
REPORT_DIR = Path("reports")
UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

SUPPORTED_FORMATS = ['.html', '.htm', '.txt', '.csv', '.xml', '.pdf']

st.set_page_config(
    page_title="FTK Report Simplifier",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Dark Mode CSS ────────────────────────────────────────────────────────────

st.markdown("""
<style>
:root {
    --bg: #0f0f1a;
    --surface: #1a1a2e;
    --surface2: #16213e;
    --accent: #0f3460;
    --text: #e0e0e0;
    --muted: #888;
}
.stApp { background-color: var(--bg); color: var(--text); }
.stSidebar { background-color: var(--surface); }
.stSidebar .css-1d391kg { background-color: var(--surface); }
[data-testid="stMetricValue"] { color: #fff; font-size: 2rem; font-weight: 700; }
[data-testid="stMetricLabel"] { color: var(--muted); }
.stAlert { border-radius: 8px; }

/* Metric cards */
.metric-card {
    background: var(--surface);
    border-radius: 10px;
    padding: 1.2rem;
    text-align: center;
    border: 1px solid var(--accent);
    margin-bottom: 0.5rem;
}
.metric-val { font-size: 2.2rem; font-weight: 900; color: #fff; }
.metric-lbl { font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem; }

/* Risk badge */
.risk-badge-LOW    { background:#1a3a2a; color:#2ecc71; }
.risk-badge-MEDIUM { background:#3a3010; color:#f39c12; }
.risk-badge-HIGH   { background:#3a1010; color:#e74c3c; }
.risk-badge-CRITICAL { background:#2a0a3a; color:#8e44ad; }
.risk-badge {
    display:inline-block; padding:0.4rem 1.2rem;
    border-radius:20px; font-weight:700; font-size:1.1rem;
}

/* Section headers */
.section-header {
    font-size: 1.1rem; font-weight: 700; color: #fff;
    border-left: 4px solid #0f3460;
    padding-left: 0.7rem; margin: 1rem 0 0.5rem;
}
/* Table styling */
.ftk-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
.ftk-table th { background: var(--accent); color: #fff; padding: 0.5rem 0.8rem; text-align: left; }
.ftk-table td { padding: 0.4rem 0.8rem; border-bottom: 1px solid var(--surface2); }

/* Indicator pill */
.ind-critical { background:#8e44ad22; border-left:3px solid #8e44ad; }
.ind-high { background:#e74c3c22; border-left:3px solid #e74c3c; }
.ind-medium { background:#f39c1222; border-left:3px solid #f39c12; }
.ind-low { background:#2ecc7122; border-left:3px solid #2ecc71; }
.indicator-card {
    border-radius:0 8px 8px 0; padding:0.8rem; margin-bottom:0.6rem;
}
</style>
""", unsafe_allow_html=True)


# ─── Session State Init ───────────────────────────────────────────────────────

def init_session():
    defaults = {
        'parsed_data': None,
        'analysis_results': None,
        'risk_results': None,
        'summary': None,
        'report_gen': None,
        'charts': None,
        'filename': None,
        'openai_key': '',
        'case_history': [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_session()


# ─── Processing Pipeline ─────────────────────────────────────────────────────

def run_pipeline(file_bytes: bytes, filename: str, openai_key: str = '') -> bool:
    """Parse → Analyze → Score → Summarize → Build charts."""
    try:
        with st.spinner("🔬 Parsing forensic report..."):
            parser = FTKReportParser()
            parsed = parser.parse(file_bytes, filename)

        with st.spinner("🧠 Analyzing findings..."):
            analyzer = ForensicAnalyzer(parsed)
            analysis = analyzer.analyze()

        with st.spinner("⚠️ Calculating risk score..."):
            engine = RiskEngine(parsed, analysis)
            risk = engine.calculate()

        with st.spinner("📝 Generating summary..."):
            summarizer = AISummaryGenerator(parsed, analysis, risk, api_key=openai_key)
            summary = summarizer.generate()

        with st.spinner("📊 Building visualizations..."):
            charts = DashboardCharts(parsed, analysis, risk)
            report_gen = ReportGenerator(parsed, analysis, risk, summary)

        # Store in session
        st.session_state.parsed_data = parsed
        st.session_state.analysis_results = analysis
        st.session_state.risk_results = risk
        st.session_state.summary = summary
        st.session_state.charts = charts
        st.session_state.report_gen = report_gen
        st.session_state.filename = filename

        # Track case history
        st.session_state.case_history.append({
            'filename': filename,
            'case_name': parsed.get('case_info', {}).get('case_name', 'Unknown'),
            'risk_level': risk.get('threat_level'),
            'risk_score': risk.get('total_score'),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
        })

        # Save uploaded file
        save_path = UPLOAD_DIR / f"{hashlib.md5(file_bytes).hexdigest()[:8]}_{filename}"
        save_path.write_bytes(file_bytes)
        logger.info(f"Saved upload: {save_path}")

        return True

    except Exception as e:
        st.error(f"❌ Processing failed: {str(e)}")
        logger.exception(f"Pipeline error for {filename}: {e}")
        return False


# ─── Sidebar ─────────────────────────────────────────────────────────────────

def render_sidebar():
    with st.sidebar:
        st.markdown("## 🔍 FTK Simplifier")
        st.markdown("*Digital Forensics Made Simple*")
        st.divider()

        page = st.radio(
            "Navigation",
            ["📤 Upload & Analyze", "📊 Dashboard", "🔎 Findings", "📅 Timeline", "📤 Export", "📁 Case History"],
            label_visibility="collapsed"
        )

        st.divider()

        # OpenAI Key
        with st.expander("⚙️ AI Settings"):
            st.session_state.openai_key = st.text_input(
                "OpenAI API Key (optional)",
                value=st.session_state.openai_key,
                type="password",
                help="Leave blank to use rule-based summaries."
            )
            if st.session_state.openai_key:
                st.success("✅ AI summaries enabled")
            else:
                st.info("ℹ️ Using rule-based summaries")

        # Current case info
        if st.session_state.parsed_data:
            st.divider()
            case_info = st.session_state.parsed_data.get('case_info', {})
            risk = st.session_state.risk_results
            level = risk.get('threat_level', '?')
            score = risk.get('total_score', 0)
            st.markdown(f"**Current Case**")
            st.markdown(f"`{case_info.get('case_name', 'Unknown')}`")
            st.markdown(
                f"<span class='risk-badge risk-badge-{level}'>{level} ({score})</span>",
                unsafe_allow_html=True
            )

        st.divider()
        st.caption("v1.0 | Built with Streamlit + ReportLab")

    return page


# ─── Page: Upload ─────────────────────────────────────────────────────────────

def page_upload():
    st.title("📤 Upload & Analyze FTK Report")
    st.markdown("Upload an FTK forensic report to automatically generate a simplified investigation summary.")

    col1, col2 = st.columns([2, 1])

    with col1:
        uploaded = st.file_uploader(
            "Drop your FTK report here",
            type=['html', 'htm', 'txt', 'csv', 'xml', 'pdf'],
            help="Supported formats: HTML, HTM, TXT, CSV, XML, PDF"
        )

        if uploaded:
            st.success(f"✅ File loaded: **{uploaded.name}** ({uploaded.size:,} bytes)")

            # File preview
            with st.expander("📄 File Preview"):
                ext = os.path.splitext(uploaded.name)[1].lower()
                if ext in ['.txt', '.csv', '.xml', '.html', '.htm']:
                    preview_text = uploaded.read(4096).decode('utf-8', errors='replace')
                    st.code(preview_text, language='text')
                    uploaded.seek(0)
                elif ext == '.pdf':
                    st.info("PDF preview not available — will be processed automatically.")
                else:
                    st.info("Binary file — will be processed automatically.")

            if st.button("🚀 Analyze Report", type="primary", use_container_width=True):
                file_bytes = uploaded.read()
                success = run_pipeline(
                    file_bytes, uploaded.name,
                    st.session_state.openai_key
                )
                if success:
                    st.success("✅ Analysis complete! Navigate to **Dashboard** to view results.")
                    st.balloons()

    with col2:
        st.markdown("### 📋 Supported Formats")
        formats = {
            '📄 HTML': 'AccessData FTK HTML reports',
            '📝 TXT': 'Plain text forensic logs',
            '📊 CSV': 'Spreadsheet-format reports',
            '🗂️ XML': 'Structured XML exports',
            '📕 PDF': 'PDF investigation reports',
        }
        for fmt, desc in formats.items():
            st.markdown(f"**{fmt}** — {desc}")

        st.divider()
        st.markdown("### 🔒 Security")
        st.markdown(
            "All files are processed locally and stored only in the `uploads/` directory. "
            "No data is sent to external services unless an OpenAI API key is configured."
        )

    # Demo / sample usage
    with st.expander("🧪 Test with Sample Data"):
        if st.button("Generate & Load Sample Report"):
            sample = _generate_sample_report()
            success = run_pipeline(sample.encode('utf-8'), "sample_ftk_report.txt", st.session_state.openai_key)
            if success:
                st.success("✅ Sample report loaded! Navigate to **Dashboard**.")


# ─── Page: Dashboard ─────────────────────────────────────────────────────────

def page_dashboard():
    if not st.session_state.parsed_data:
        st.warning("⚠️ No report loaded. Please upload a report first.")
        return

    data = st.session_state.parsed_data
    analysis = st.session_state.analysis_results
    risk = st.session_state.risk_results
    summary = st.session_state.summary
    charts: DashboardCharts = st.session_state.charts
    stats = analysis.get('summary_stats', {})
    case_info = data.get('case_info', {})

    st.title(f"📊 Dashboard — {case_info.get('case_name', 'Investigation')}")

    # Top metrics
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    metrics = [
        (col1, stats.get('total_files', 0), "Total Files", "📁"),
        (col2, stats.get('suspicious_files', 0), "Suspicious Files", "🚨"),
        (col3, stats.get('deleted_files', 0), "Deleted Files", "🗑️"),
        (col4, stats.get('usb_devices', 0), "USB Devices", "🔌"),
        (col5, stats.get('unique_keywords', 0), "Keywords Hit", "🔑"),
        (col6, stats.get('malicious_domains', 0), "Malicious Domains", "⚠️"),
    ]
    for col, val, label, icon in metrics:
        with col:
            st.metric(f"{icon} {label}", val)

    st.divider()

    # Gauge + summary
    col_gauge, col_summary = st.columns([1, 2])
    with col_gauge:
        st.plotly_chart(charts.risk_gauge(), use_container_width=True, config={'displayModeBar': False})
        level = risk.get('threat_level', 'UNKNOWN')
        st.markdown(
            f"<div style='text-align:center'>"
            f"<span class='risk-badge risk-badge-{level}'>{level}</span>"
            f"</div>",
            unsafe_allow_html=True
        )
        st.markdown(
            f"<p style='text-align:center;color:#888;font-size:0.85rem;margin-top:0.5rem'>"
            f"{risk.get('description','')[:160]}...</p>",
            unsafe_allow_html=True
        )

    with col_summary:
        st.markdown("### 📝 Executive Summary")
        st.markdown(
            f"<div style='background:#1a1a2e;border-left:4px solid {risk.get('color','#0f3460')};"
            f"padding:1rem;border-radius:0 8px 8px 0;line-height:1.8;'>"
            f"{summary.get('executive_summary', 'No summary available.')}</div>",
            unsafe_allow_html=True
        )
        method = summary.get('method_used', 'Rule-Based')
        st.caption(f"Summary generated by: {method}")

    st.divider()

    # Charts row 1
    col_pie, col_keyword = st.columns(2)
    with col_pie:
        st.plotly_chart(charts.file_type_pie(), use_container_width=True)
    with col_keyword:
        st.plotly_chart(charts.keyword_bar(), use_container_width=True)

    # Charts row 2
    col_stats, col_risk = st.columns(2)
    with col_stats:
        st.plotly_chart(charts.file_stats_bar(), use_container_width=True)
    with col_risk:
        st.plotly_chart(charts.risk_breakdown_bar(), use_container_width=True)

    # Domain chart
    if data.get('browser_history'):
        st.plotly_chart(charts.domain_bar(), use_container_width=True)


# ─── Page: Findings ───────────────────────────────────────────────────────────

def page_findings():
    if not st.session_state.parsed_data:
        st.warning("⚠️ No report loaded. Please upload a report first.")
        return

    data = st.session_state.parsed_data
    analysis = st.session_state.analysis_results
    charts: DashboardCharts = st.session_state.charts

    st.title("🔎 Findings")

    # Search bar
    search_term = st.text_input("🔍 Search findings...", placeholder="Filter by filename, keyword, domain...")

    tab_susp, tab_deleted, tab_kw, tab_browser, tab_usb, tab_indicators = st.tabs([
        "🚨 Suspicious Files", "🗑️ Deleted Files", "🔑 Keywords",
        "🌐 Browser History", "🔌 USB Activity", "⚠️ Threat Indicators"
    ])

    with tab_susp:
        susp_files = data.get('suspicious_files', [])
        if search_term:
            susp_files = [f for f in susp_files if search_term.lower() in f.get('name', '').lower()]
        st.markdown(f"**{len(susp_files)} suspicious file(s) detected**")
        if susp_files:
            df = pd.DataFrame(susp_files)[['name', 'size', 'timestamp']].rename(
                columns={'name': 'Filename', 'size': 'Size', 'timestamp': 'Timestamp'}
            )
            st.dataframe(df, use_container_width=True)
            st.download_button("⬇️ Export CSV", df.to_csv(index=False), "suspicious_files.csv", "text/csv")
        else:
            st.success("✅ No suspicious files detected.")

    with tab_deleted:
        del_files = data.get('deleted_files', [])
        if search_term:
            del_files = [f for f in del_files if search_term.lower() in f.get('name', '').lower()]
        st.markdown(f"**{len(del_files)} deleted file(s) found**")
        if del_files:
            df = pd.DataFrame(del_files)[['name', 'size', 'timestamp']].rename(
                columns={'name': 'Filename', 'size': 'Size', 'timestamp': 'Timestamp'}
            )
            st.dataframe(df, use_container_width=True)
        else:
            st.success("✅ No deleted files detected.")

    with tab_kw:
        kw_hits = data.get('keyword_hits', [])
        if search_term:
            kw_hits = [h for h in kw_hits if search_term.lower() in h.get('keyword', '').lower()]
        if kw_hits:
            df = pd.DataFrame(kw_hits).rename(
                columns={'keyword': 'Keyword', 'count': 'Occurrences', 'locations': 'Locations'}
            )
            st.dataframe(df, use_container_width=True)
            st.plotly_chart(charts.keyword_bar(), use_container_width=True)
        else:
            st.success("✅ No keyword hits found.")

    with tab_browser:
        history = data.get('browser_history', [])
        if search_term:
            history = [h for h in history if search_term.lower() in h.get('url', '').lower()
                       or search_term.lower() in h.get('domain', '').lower()]
        st.markdown(f"**{len(history)} URL(s) found in browser history**")
        if history:
            df = pd.DataFrame(history)
            if 'suspicious' in df.columns:
                df['suspicious'] = df['suspicious'].map({True: '⚠️ Yes', False: '—'})
            st.dataframe(df[['domain', 'url', 'suspicious']].rename(
                columns={'domain': 'Domain', 'url': 'URL', 'suspicious': 'Flagged'}
            ), use_container_width=True)
            st.plotly_chart(charts.domain_bar(), use_container_width=True)
        else:
            st.info("No browser history extracted.")

    with tab_usb:
        usb = data.get('usb_activity', [])
        st.markdown(f"**{len(usb)} USB device(s) detected**")
        if usb:
            df = pd.DataFrame(usb).rename(columns={
                'device_name': 'Device', 'vendor': 'Vendor',
                'serial': 'Serial', 'timestamp': 'Timestamp'
            })
            st.dataframe(df, use_container_width=True)
        else:
            st.success("✅ No USB activity detected.")

    with tab_indicators:
        indicators = analysis.get('threat_indicators', [])
        st.plotly_chart(charts.threat_indicators_chart(), use_container_width=True)
        for ind in indicators:
            sev = ind.get('severity', 'LOW').lower()
            st.markdown(
                f"<div class='indicator-card ind-{sev}'>"
                f"<b>[{ind.get('severity')}] {ind.get('type')}</b><br>"
                f"{ind.get('detail','')}<br>"
                f"<small style='color:#888;'>{', '.join(ind.get('items',[])[:5])}</small>"
                f"</div>",
                unsafe_allow_html=True
            )


# ─── Page: Timeline ───────────────────────────────────────────────────────────

def page_timeline():
    if not st.session_state.parsed_data:
        st.warning("⚠️ No report loaded. Please upload a report first.")
        return

    data = st.session_state.parsed_data
    charts: DashboardCharts = st.session_state.charts
    timeline = data.get('timeline', [])

    st.title("📅 Forensic Timeline")
    st.markdown(f"**{len(timeline)} chronological event(s) extracted**")

    if timeline:
        # Filter controls
        col1, col2 = st.columns(2)
        with col1:
            event_types = list({e['event_type'] for e in timeline})
            selected_types = st.multiselect(
                "Filter by event type",
                options=event_types,
                default=event_types
            )
        with col2:
            search = st.text_input("Search descriptions", placeholder="e.g. USB, delete, browser...")

        filtered = [
            e for e in timeline
            if e['event_type'] in selected_types
            and (not search or search.lower() in e['description'].lower())
        ]

        st.plotly_chart(charts.timeline_scatter(), use_container_width=True)

        df = pd.DataFrame(filtered)[['timestamp', 'event_type', 'description']].rename(
            columns={'timestamp': 'Timestamp', 'event_type': 'Event Type', 'description': 'Description'}
        )
        st.dataframe(df, use_container_width=True, height=400)
        st.download_button("⬇️ Export Timeline CSV", df.to_csv(index=False), "timeline.csv", "text/csv")
    else:
        st.info("No timestamped events could be extracted from this report.")


# ─── Page: Export ─────────────────────────────────────────────────────────────

def page_export():
    if not st.session_state.report_gen:
        st.warning("⚠️ No report loaded. Please upload a report first.")
        return

    rg: ReportGenerator = st.session_state.report_gen
    case_name = st.session_state.parsed_data.get('case_info', {}).get('case_name', 'report')
    safe_name = "".join(c if c.isalnum() or c in '-_' else '_' for c in case_name)

    st.title("📤 Export Reports")
    st.markdown("Download the investigation report in your preferred format.")

    col1, col2 = st.columns(2)

    with col1:
        # PDF
        st.markdown("### 📕 PDF Report")
        st.markdown("Full formatted report with tables, risk gauge, and recommendations.")
        try:
            pdf_bytes = rg.generate_pdf()
            st.download_button(
                "⬇️ Download PDF",
                data=pdf_bytes,
                file_name=f"ftk_report_{safe_name}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation error: {e}")

        st.divider()

        # TXT
        st.markdown("### 📝 Plain Text Report")
        st.markdown("Human-readable text report for archiving or printing.")
        txt_content = rg.generate_txt()
        st.download_button(
            "⬇️ Download TXT",
            data=txt_content.encode('utf-8'),
            file_name=f"ftk_report_{safe_name}.txt",
            mime="text/plain",
            use_container_width=True,
        )

    with col2:
        # HTML
        st.markdown("### 🌐 HTML Report")
        st.markdown("Interactive styled HTML — open in any browser.")
        html_content = rg.generate_html()
        st.download_button(
            "⬇️ Download HTML",
            data=html_content.encode('utf-8'),
            file_name=f"ftk_report_{safe_name}.html",
            mime="text/html",
            use_container_width=True,
        )

        st.divider()

        # JSON
        st.markdown("### 🗂️ JSON Export")
        st.markdown("Machine-readable export for integration with other tools.")
        json_content = rg.generate_json()
        st.download_button(
            "⬇️ Download JSON",
            data=json_content.encode('utf-8'),
            file_name=f"ftk_report_{safe_name}.json",
            mime="application/json",
            use_container_width=True,
        )

        st.divider()

        # CSV
        st.markdown("### 📊 CSV File Listing")
        st.markdown("All extracted files as a spreadsheet-ready CSV.")
        csv_content = rg.generate_csv()
        st.download_button(
            "⬇️ Download CSV",
            data=csv_content.encode('utf-8'),
            file_name=f"ftk_files_{safe_name}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    # Preview HTML inline
    st.divider()
    with st.expander("👁️ Preview HTML Report"):
        st.components.v1.html(html_content, height=800, scrolling=True)


# ─── Page: Case History ───────────────────────────────────────────────────────

def page_case_history():
    st.title("📁 Case History")
    history = st.session_state.case_history

    if not history:
        st.info("No cases analyzed yet in this session.")
        return

    st.markdown(f"**{len(history)} case(s) processed this session**")

    df = pd.DataFrame(history).rename(columns={
        'filename': 'Filename',
        'case_name': 'Case Name',
        'risk_level': 'Threat Level',
        'risk_score': 'Risk Score',
        'timestamp': 'Analyzed At',
    })
    st.dataframe(df, use_container_width=True)

    # Simple risk level comparison chart
    if len(history) > 1:
        import plotly.graph_objects as go
        fig = go.Figure(go.Bar(
            x=[h['case_name'] for h in history],
            y=[h['risk_score'] for h in history],
            marker_color=['#2ecc71' if h['risk_level'] == 'LOW'
                          else '#f39c12' if h['risk_level'] == 'MEDIUM'
                          else '#e74c3c' if h['risk_level'] == 'HIGH'
                          else '#8e44ad' for h in history],
            text=[h['risk_level'] for h in history],
            textposition='outside',
        ))
        fig.update_layout(
            paper_bgcolor='#1a1a2e', plot_bgcolor='#16213e',
            font=dict(color='#e0e0e0'),
            title='Risk Score Comparison Across Cases',
            xaxis=dict(color='#888'), yaxis=dict(title='Risk Score', color='#888'),
            height=350,
        )
        st.plotly_chart(fig, use_container_width=True)


# ─── Sample Report Generator ─────────────────────────────────────────────────

def _generate_sample_report() -> str:
    return """FTK Forensic Report
Case Name: Operation Nightfall
Case Number: INV-2024-0047
Investigator: Agent Sarah Chen
Report Date: 2024-03-15
Evidence Item: Dell Laptop - Serial: DL7829XFKR

=== FILE LISTINGS ===
2024-03-10 09:12:33  system.exe         1.2 MB   C:\\Windows\\Temp\\
2024-03-10 09:14:55  payload.bat        4 KB     C:\\Users\\john\\AppData\\
2024-03-10 09:22:01  exfil.ps1          12 KB    C:\\Windows\\System32\\
2024-03-11 14:30:00  archive.zip        45 MB    C:\\Users\\john\\Desktop\\
2024-03-11 14:35:22  document.docx      120 KB   C:\\Users\\john\\Documents\\
2024-03-12 08:45:00  .hidden_config     2 KB     C:\\Users\\john\\
2024-03-12 10:00:00  keylogger.dll      88 KB    C:\\Windows\\System32\\
2024-03-12 10:05:00  credentials.txt    3 KB     C:\\Temp\\
2024-03-12 10:10:00  wallet.dat         500 KB   C:\\Users\\john\\AppData\\Roaming\\Bitcoin\\

=== DELETED FILES ===
2024-03-12 22:00:00  evidence.log  (Recovered from $Recycle.Bin)
2024-03-12 22:05:00  chat_logs.txt (Recovered from $Recycle.Bin)
2024-03-12 22:10:00  transfer.exe  (Recovered from $Recycle.Bin)

=== USB DEVICE ACTIVITY ===
USB Device: SanDisk Cruzer 32GB
VID_0781&PID_5572
Serial: AA010201222B4B38A1B0
Connected: 2024-03-12 08:30:00

USB Device: Kingston DataTraveler
VID_0951&PID_1666
Serial: 001A92098E234B2A
Connected: 2024-03-11 18:00:00

=== BROWSER HISTORY ===
https://www.google.com/search?q=how+to+hide+files+windows
https://pastebin.com/xkA92ndZ
https://bitcoin.org/en/
https://www.blockchain.info/wallet
https://hackforums.net/showthread.php?tid=5291
https://github.com/user/tool
https://mail.protonmail.com/inbox
https://www.youtube.com/watch?v=dQw4w9WgXcQ
https://download.site/malware_tool.exe
https://exploit.in/forum/post/1234

=== KEYWORDS ===
password found in credentials.txt at line 1
bitcoin found in wallet.dat and browser history
credentials found in C:\\Temp\\credentials.txt
hack found in browser search history
malware detected via signature match on keylogger.dll
wallet found in C:\\Users\\john\\AppData\\Roaming\\Bitcoin\\
confidential found in document.docx

=== KEYWORD COUNTS ===
password: 12 occurrences
bitcoin: 8 occurrences
credentials: 5 occurrences
hack: 3 occurrences
malware: 6 occurrences
wallet: 10 occurrences
bank: 2 occurrences
confidential: 4 occurrences
crypto: 7 occurrences
hacker: 2 occurrences

=== TIMELINE ===
2024-03-10 09:12:33  File Created: system.exe
2024-03-10 09:14:55  File Created: payload.bat
2024-03-11 14:30:00  File Created: archive.zip - possible data staging
2024-03-11 18:00:00  USB Device Connected: Kingston DataTraveler
2024-03-12 08:30:00  USB Device Connected: SanDisk Cruzer
2024-03-12 08:45:00  File Accessed: .hidden_config
2024-03-12 10:00:00  Executable Launched: keylogger.dll
2024-03-12 22:00:00  File Deleted: evidence.log
2024-03-12 22:05:00  File Deleted: chat_logs.txt
2024-03-12 22:10:00  File Deleted: transfer.exe
"""


# ─── Main Router ──────────────────────────────────────────────────────────────

def main():
    page = render_sidebar()

    if page == "📤 Upload & Analyze":
        page_upload()
    elif page == "📊 Dashboard":
        page_dashboard()
    elif page == "🔎 Findings":
        page_findings()
    elif page == "📅 Timeline":
        page_timeline()
    elif page == "📤 Export":
        page_export()
    elif page == "📁 Case History":
        page_case_history()


if __name__ == "__main__":
    main()
