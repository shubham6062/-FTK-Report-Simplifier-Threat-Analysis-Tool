# 🔍 FTK Report Simplifier & Threat Analysis Tool

> **Transform complex FTK forensic reports into clear, actionable intelligence — instantly.**

A production-ready Python + Streamlit application that ingests AccessData FTK forensic reports and automatically generates easy-to-understand investigation summaries for non-technical stakeholders, complete with risk scoring, visualizations, and multi-format exports.

---

## 📸 Screenshots

```
[ Upload Page ]           [ Dashboard ]             [ Findings ]
┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│ Drop FTK     │          │ Risk Gauge   │          │ Susp. Files  │
│ Report Here  │   ──►    │ Score: 87    │   ──►    │ Keywords     │
│              │          │ Level: HIGH  │          │ Browser Hist │
│ .html .pdf   │          │ Charts...    │          │ USB Activity │
└──────────────┘          └──────────────┘          └──────────────┘
```

---

## ✨ Features

| Feature | Description |
|---|---|
| **Multi-Format Parsing** | HTML, PDF, TXT, CSV, XML FTK reports |
| **Automatic Extraction** | Case info, files, keywords, browser history, USB activity |
| **Risk Scoring Engine** | Weighted scoring formula → LOW / MEDIUM / HIGH / CRITICAL |
| **AI Summaries** | OpenAI GPT-4 powered OR built-in rule-based engine |
| **Dark Mode Dashboard** | Professional Plotly charts with dark theme |
| **Forensic Timeline** | Chronological event reconstruction |
| **Multi-Format Export** | PDF, HTML, TXT, JSON, CSV |
| **Case History** | Track and compare multiple investigations |
| **Search & Filter** | Filter findings across all tabs |

---

## 🚀 Quick Start

### 1. Clone / Download

```bash
git clone https://github.com/shubham6062/-FTK-Report-Simplifier-Threat-Analysis-Tool.git
cd FTK_Report_Simplifier
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
streamlit run app.py
```

The app will open at **http://localhost:8501**

---

## 📁 Project Structure

```
FTK_Report_Simplifier/
│
├── app.py               # Main Streamlit UI & page routing
├── parser.py            # Multi-format FTK report parser
├── analyzer.py          # Forensic analysis & threat detection
├── risk_engine.py       # Risk scoring engine
├── ai_summary.py        # AI / rule-based summary generator
├── report_generator.py  # PDF, HTML, TXT, JSON, CSV export
├── dashboard.py         # Plotly visualization charts
│
├── requirements.txt     # Python dependencies
├── README.md            # This file
│
├── uploads/             # Uploaded report files (auto-created)
└── reports/             # Generated reports (auto-created)
```

---

## 🧠 How It Works

```
FTK Report (.html/.pdf/.txt/.csv/.xml)
          │
          ▼
    [parser.py] ──── Extracts: case info, files, keywords,
          │           browser history, USB, timeline
          ▼
    [analyzer.py] ── Identifies: threat indicators, domain
          │           analysis, file type distribution
          ▼
    [risk_engine.py] ─ Calculates: weighted risk score,
          │             threat level (LOW → CRITICAL)
          ▼
    [ai_summary.py] ─ Generates: executive + technical
          │            summary (OpenAI or rule-based)
          ▼
    [dashboard.py] ─ Builds: Plotly charts (gauge, pie,
          │           bar, scatter timeline)
          ▼
    [report_generator.py] ─ Exports: PDF, HTML, TXT, JSON, CSV
```

---

## ⚖️ Risk Scoring Formula

| Finding | Points |
|---|---|
| Each Deleted File | +5 |
| Each Executable File | +10 |
| Each Suspicious Keyword Occurrence | +3 |
| USB Activity (any) | +10 flat |
| Each Known Malicious Domain | +20 |
| Each Hidden File | +3 |
| Each Archive File | +2 |

| Score Range | Threat Level |
|---|---|
| 0 – 30 | 🟢 LOW |
| 31 – 60 | 🟡 MEDIUM |
| 61 – 100 | 🔴 HIGH |
| 100+ | 🟣 CRITICAL |

---

## 🔑 Keyword Detection

The tool automatically scans for these sensitive keywords:

`password` · `bitcoin` · `wallet` · `hack` · `hacker` · `malware` · `crypto` · `credentials` · `bank` · `confidential`

---

## 🤖 AI Summaries (Optional)

To enable OpenAI-powered summaries:

1. Obtain an API key from [platform.openai.com](https://platform.openai.com)
2. Enter it in the **⚙️ AI Settings** panel in the sidebar
3. The app will use `gpt-4o-mini` to generate tailored summaries

Without a key, the built-in rule-based engine automatically generates accurate summaries from the extracted data — **no API key required**.

---

## 📤 Supported Export Formats

| Format | Contents |
|---|---|
| **PDF** | Full formatted report with tables, risk breakdown, recommendations |
| **HTML** | Interactive dark-mode web report, viewable in any browser |
| **TXT** | Plain text, printer-friendly report |
| **JSON** | Machine-readable export for SIEM/SOAR integration |
| **CSV** | File listing spreadsheet |

---

## 🔒 Security & Privacy

- All processing happens **locally** on your machine
- Files are stored only in the `uploads/` directory
- No data is transmitted externally unless OpenAI API key is configured
- The `uploads/` and `reports/` directories should be secured appropriately in production

---

## 📦 Dependencies

```
streamlit       >= 1.32.0   # Web UI framework
pandas          >= 2.2.0    # Data manipulation
beautifulsoup4  >= 4.12.3   # HTML parsing
PyPDF2          >= 3.0.1    # PDF text extraction
reportlab       >= 4.1.0    # PDF generation
plotly          >= 5.20.0   # Interactive charts
openai          >= 1.14.0   # Optional AI summaries
lxml            >= 5.1.0    # Fast XML/HTML parser
python-dateutil >= 2.9.0    # Timestamp parsing
```

---

## 🧪 Testing with Sample Data

The app includes a built-in sample report for testing:

1. Go to **Upload & Analyze**
2. Expand **🧪 Test with Sample Data**
3. Click **Generate & Load Sample Report**
4. Navigate to **Dashboard** to see results

---

## 🛠 Troubleshooting

**PDF generation fails**
```bash
pip install reportlab --upgrade
```

**PDF parsing fails**
```bash
pip install PyPDF2 --upgrade
```

**XML/HTML parsing issues**
```bash
pip install lxml --upgrade
```

**Streamlit version issues**
```bash
pip install streamlit --upgrade
```

---

## 🗺️ Roadmap

- [ ] Hash verification against VirusTotal API
- [ ] Registry hive parsing
- [ ] Memory dump analysis
- [ ] STIX/TAXII threat intelligence integration
- [ ] Multi-language report export
- [ ] Docker containerization
- [ ] REST API endpoint

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 🙏 Credits

Built with:
- [Streamlit](https://streamlit.io) — web UI
- [ReportLab](https://www.reportlab.com) — PDF generation
- [Plotly](https://plotly.com) — data visualizations
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) — HTML parsing
- [OpenAI](https://openai.com) — optional AI summaries

---

*"Making forensics accessible to everyone."*
