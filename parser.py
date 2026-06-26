"""
parser.py - FTK Report Parser Module
Handles parsing of FTK forensic reports in HTML, TXT, CSV, XML, and PDF formats.
"""

import os
import re
import csv
import logging
import xml.etree.ElementTree as ET
from io import StringIO, BytesIO
from datetime import datetime
from typing import Optional

import pandas as pd
from bs4 import BeautifulSoup

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

logger = logging.getLogger(__name__)


class FTKReportParser:
    """
    Parses FTK forensic reports from multiple formats and extracts
    structured data for analysis.
    """

    SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.jar'}
    ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
    DOC_EXTENSIONS = {'.doc', '.docx', '.xls', '.xlsx', '.pdf', '.txt'}

    SUSPICIOUS_KEYWORDS = [
        'password', 'bitcoin', 'wallet', 'hack', 'hacker',
        'malware', 'crypto', 'credentials', 'bank', 'confidential'
    ]

    SUSPICIOUS_DOMAINS = [
        'pastebin.com', 'temp-mail.org', 'guerrillamail.com',
        'darkweb', 'onion', 'tor2web', 'protonmail',
        'exploit.in', 'hackforums', 'nulled.to'
    ]

    def __init__(self):
        self.raw_text = ""
        self.parsed_data = {}

    def parse(self, file_content: bytes, filename: str) -> dict:
        """
        Main parse dispatcher - routes to format-specific parser.

        Args:
            file_content: Raw file bytes
            filename: Original filename (used to determine format)

        Returns:
            dict: Structured parsed data
        """
        ext = os.path.splitext(filename)[1].lower()
        logger.info(f"Parsing file: {filename} (extension: {ext})")

        try:
            if ext == '.html' or ext == '.htm':
                self.raw_text = self._parse_html(file_content)
            elif ext == '.pdf':
                self.raw_text = self._parse_pdf(file_content)
            elif ext == '.csv':
                return self._parse_csv(file_content, filename)
            elif ext == '.xml':
                self.raw_text = self._parse_xml(file_content)
            elif ext == '.txt':
                self.raw_text = file_content.decode('utf-8', errors='ignore')
            else:
                raise ValueError(f"Unsupported file format: {ext}")

            return self._extract_all()
        except Exception as e:
            logger.error(f"Error parsing file {filename}: {e}")
            raise

    # ─── Format-specific parsers ──────────────────────────────────────────────

    def _parse_html(self, content: bytes) -> str:
        """Extract text from HTML FTK report."""
        soup = BeautifulSoup(content, 'lxml')
        # Remove script/style tags
        for tag in soup(['script', 'style']):
            tag.decompose()
        return soup.get_text(separator='\n', strip=True)

    def _parse_pdf(self, content: bytes) -> str:
        """Extract text from PDF FTK report."""
        if not PDF_AVAILABLE:
            raise ImportError("PyPDF2 is required for PDF parsing.")
        reader = PyPDF2.PdfReader(BytesIO(content))
        text_parts = []
        for page in reader.pages:
            text_parts.append(page.extract_text() or "")
        return "\n".join(text_parts)

    def _parse_xml(self, content: bytes) -> str:
        """Extract text from XML FTK report."""
        try:
            root = ET.fromstring(content)
            texts = []
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    texts.append(f"{elem.tag}: {elem.text.strip()}")
                for k, v in elem.attrib.items():
                    texts.append(f"{elem.tag}@{k}: {v}")
            return "\n".join(texts)
        except ET.ParseError as e:
            logger.warning(f"XML parse error, falling back to raw text: {e}")
            return content.decode('utf-8', errors='ignore')

    def _parse_csv(self, content: bytes, filename: str) -> dict:
        """Parse CSV format FTK report directly into structured data."""
        try:
            df = pd.read_csv(BytesIO(content), encoding='utf-8', errors='replace')
        except Exception:
            df = pd.read_csv(BytesIO(content), encoding='latin-1', errors='replace')

        self.raw_text = df.to_string()
        data = self._extract_all()

        # CSV-specific: treat rows as file listings
        col_lower = {c.lower(): c for c in df.columns}
        file_col = col_lower.get('name') or col_lower.get('filename') or col_lower.get('file name')
        path_col = col_lower.get('path') or col_lower.get('filepath')
        size_col = col_lower.get('size') or col_lower.get('file size')
        ts_col = col_lower.get('created') or col_lower.get('modified') or col_lower.get('timestamp')

        if file_col:
            files = []
            for _, row in df.iterrows():
                fname = str(row.get(file_col, ''))
                fpath = str(row.get(path_col, '')) if path_col else ''
                fsize = str(row.get(size_col, '')) if size_col else ''
                fts = str(row.get(ts_col, '')) if ts_col else ''
                files.append({
                    'name': fname, 'path': fpath,
                    'size': fsize, 'timestamp': fts
                })
            data['file_listings'] = files
            data['total_files'] = len(files)
            data['suspicious_files'] = [
                f for f in files
                if os.path.splitext(f['name'])[1].lower() in self.SUSPICIOUS_EXTENSIONS
            ]
            data['deleted_files'] = [
                f for f in files
                if 'recycl' in f.get('path', '').lower() or 'deleted' in f.get('name', '').lower()
            ]

        return data

    # ─── Extraction helpers ───────────────────────────────────────────────────

    def _extract_all(self) -> dict:
        """Run all extractors on self.raw_text and aggregate results."""
        data = {}
        data['case_info'] = self._extract_case_info()
        data['file_listings'] = self._extract_file_listings()
        data['deleted_files'] = self._extract_deleted_files(data['file_listings'])
        data['hidden_files'] = self._extract_hidden_files(data['file_listings'])
        data['suspicious_files'] = self._extract_suspicious_files(data['file_listings'])
        data['archive_files'] = self._extract_archive_files(data['file_listings'])
        data['executable_files'] = [
            f for f in data['file_listings']
            if os.path.splitext(f.get('name', ''))[1].lower() in {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.jar'}
        ]
        data['keyword_hits'] = self._extract_keywords()
        data['browser_history'] = self._extract_browser_history()
        data['usb_activity'] = self._extract_usb_activity()
        data['timeline'] = self._extract_timeline()
        data['total_files'] = len(data['file_listings'])
        data['raw_text'] = self.raw_text
        return data

    def _extract_case_info(self) -> dict:
        """Extract case metadata from report header."""
        info = {
            'case_name': 'Unknown',
            'investigator': 'Unknown',
            'case_number': 'Unknown',
            'date': datetime.now().strftime('%Y-%m-%d'),
            'evidence_items': []
        }

        patterns = {
            'case_name': [
                r'[Cc]ase\s+[Nn]ame[:\s]+([^\n]+)',
                r'[Cc]ase[:\s]+([^\n]+)',
            ],
            'investigator': [
                r'[Ii]nvestigator[:\s]+([^\n]+)',
                r'[Ee]xaminer[:\s]+([^\n]+)',
                r'[Aa]nalyst[:\s]+([^\n]+)',
            ],
            'case_number': [
                r'[Cc]ase\s+[Nn]umber[:\s]+([^\n]+)',
                r'[Cc]ase\s+[Nn]o[\.:\s]+([^\n]+)',
                r'[Rr]eport\s+[Nn]umber[:\s]+([^\n]+)',
            ],
            'date': [
                r'[Dd]ate[:\s]+(\d{4}-\d{2}-\d{2})',
                r'[Dd]ate[:\s]+(\d{1,2}/\d{1,2}/\d{2,4})',
                r'[Rr]eport\s+[Dd]ate[:\s]+([^\n]+)',
            ]
        }

        for field, pats in patterns.items():
            for pat in pats:
                match = re.search(pat, self.raw_text)
                if match:
                    info[field] = match.group(1).strip()
                    break

        # Extract evidence items
        evidence_pattern = r'[Ee]vidence\s+[Ii]tem[:\s]+([^\n]+)'
        info['evidence_items'] = re.findall(evidence_pattern, self.raw_text)

        return info

    def _extract_file_listings(self) -> list:
        """Extract file entries from report text."""
        files = []
        seen = set()

        # Pattern: filename with extension followed by optional size/timestamp
        file_pattern = re.compile(
            r'([A-Za-z0-9_\-\.]+\.[a-zA-Z0-9]{1,5})'
            r'(?:\s+(\d+[\.,]?\d*\s*(?:KB|MB|GB|bytes?)?)?)?'
            r'(?:\s+(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}(?::\d{2})?))?',
            re.IGNORECASE
        )

        for match in file_pattern.finditer(self.raw_text):
            fname = match.group(1)
            if fname.lower() in seen:
                continue
            # Filter out common non-file strings
            if re.match(r'^[\d\.\-]+$', fname):
                continue
            seen.add(fname.lower())
            files.append({
                'name': fname,
                'size': match.group(2) or 'Unknown',
                'timestamp': match.group(3) or 'Unknown',
                'path': ''
            })

        return files

    def _extract_deleted_files(self, file_list: list) -> list:
        """Flag files likely to be deleted (from Recycle Bin or marked deleted)."""
        deleted = []
        deleted_pattern = re.compile(
            r'(\$Recycle\.Bin|RECYCLER|Deleted|Recycle|\.deleted)',
            re.IGNORECASE
        )
        for f in file_list:
            if deleted_pattern.search(f.get('path', '') + f.get('name', '')):
                deleted.append(f)
        # Also scan raw text for deleted file references
        raw_matches = re.findall(
            r'[Dd]eleted\s+[Ff]ile[s]?[:\s]+([^\n]+)', self.raw_text
        )
        for m in raw_matches:
            fname = m.strip()
            if fname and fname not in [f['name'] for f in deleted]:
                deleted.append({'name': fname, 'size': 'Unknown', 'timestamp': 'Unknown', 'path': 'Deleted'})
        return deleted

    def _extract_hidden_files(self, file_list: list) -> list:
        """Identify hidden files (starting with dot or marked hidden)."""
        hidden = []
        for f in file_list:
            name = f.get('name', '')
            if name.startswith('.') or 'hidden' in name.lower():
                hidden.append(f)
        raw_matches = re.findall(
            r'[Hh]idden\s+[Ff]ile[s]?[:\s]+([^\n]+)', self.raw_text
        )
        for m in raw_matches:
            fname = m.strip()
            if fname:
                hidden.append({'name': fname, 'size': 'Unknown', 'timestamp': 'Unknown', 'path': 'Hidden'})
        return hidden

    def _extract_suspicious_files(self, file_list: list) -> list:
        """Filter files with suspicious extensions."""
        return [
            f for f in file_list
            if os.path.splitext(f.get('name', ''))[1].lower() in self.SUSPICIOUS_EXTENSIONS
        ]

    def _extract_archive_files(self, file_list: list) -> list:
        """Filter archive files."""
        return [
            f for f in file_list
            if os.path.splitext(f.get('name', ''))[1].lower() in self.ARCHIVE_EXTENSIONS
        ]

    def _extract_keywords(self) -> list:
        """Count keyword occurrences and record approximate locations."""
        hits = []
        text_lower = self.raw_text.lower()
        lines = self.raw_text.splitlines()

        for kw in self.SUSPICIOUS_KEYWORDS:
            count = text_lower.count(kw.lower())
            if count > 0:
                locations = []
                for i, line in enumerate(lines, 1):
                    if kw.lower() in line.lower():
                        locations.append(f"Line {i}")
                        if len(locations) >= 5:
                            break
                hits.append({
                    'keyword': kw,
                    'count': count,
                    'locations': ', '.join(locations) if locations else 'Various'
                })
        return hits

    def _extract_browser_history(self) -> list:
        """Extract URLs and browser history entries."""
        history = []
        url_pattern = re.compile(
            r'https?://[^\s\'"<>]{5,200}', re.IGNORECASE
        )
        seen_urls = set()
        for match in url_pattern.finditer(self.raw_text):
            url = match.group(0).rstrip('.,;)')
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
            except Exception:
                domain = url
            is_suspicious = any(d in domain.lower() for d in self.SUSPICIOUS_DOMAINS)
            history.append({
                'url': url,
                'domain': domain,
                'suspicious': is_suspicious
            })
        return history

    def _extract_usb_activity(self) -> list:
        """Extract USB device information."""
        devices = []

        # Match USB device descriptors
        usb_patterns = [
            r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})',
            r'USB\s+(?:Device|Drive|Flash)[:\s]+([^\n]+)',
            r'[Vv]endor[:\s]+([^\n]+)',
            r'[Ss]erial\s+[Nn]umber[:\s]+([^\n]+)',
        ]

        vid_pid = re.findall(r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})', self.raw_text)
        for vid, pid in vid_pid:
            devices.append({
                'device_name': f'USB Device VID:{vid} PID:{pid}',
                'vendor': f'VID:{vid}',
                'serial': f'PID:{pid}',
                'timestamp': 'Unknown'
            })

        # Generic USB mentions
        generic = re.findall(
            r'USB\s+(?:Device|Drive|Disk|Flash)[:\s]+([^\n]{3,80})',
            self.raw_text, re.IGNORECASE
        )
        for g in generic:
            if g.strip() not in [d['device_name'] for d in devices]:
                devices.append({
                    'device_name': g.strip(),
                    'vendor': 'Unknown',
                    'serial': 'Unknown',
                    'timestamp': 'Unknown'
                })

        # Timestamps near USB entries
        ts_pattern = re.compile(
            r'(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}(?::\d{2})?)'
        )
        for device in devices:
            if device['timestamp'] == 'Unknown':
                # Look nearby in raw text
                idx = self.raw_text.lower().find('usb')
                if idx != -1:
                    snippet = self.raw_text[max(0, idx-100):idx+200]
                    ts_match = ts_pattern.search(snippet)
                    if ts_match:
                        device['timestamp'] = ts_match.group(1)

        return devices

    def _extract_timeline(self) -> list:
        """Build a chronological timeline of forensic events."""
        events = []
        ts_pattern = re.compile(
            r'(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}(?::\d{2})?)',
            re.IGNORECASE
        )

        event_keywords = {
            'USB': 'USB Device Activity',
            'delete': 'File Deletion',
            'creat': 'File Creation',
            'modif': 'File Modification',
            'open': 'File Access',
            'exec': 'Execution',
            'run': 'Execution',
            'browser': 'Browser Activity',
            'http': 'Web Access',
            'login': 'Authentication',
            'logon': 'Authentication',
        }

        for line in self.raw_text.splitlines():
            ts_match = ts_pattern.search(line)
            if not ts_match:
                continue
            ts = ts_match.group(1)
            event_type = 'General Activity'
            for kw, label in event_keywords.items():
                if kw.lower() in line.lower():
                    event_type = label
                    break
            events.append({
                'timestamp': ts,
                'event_type': event_type,
                'description': line.strip()[:120]
            })

        # Sort chronologically
        def parse_ts(e):
            try:
                return datetime.fromisoformat(e['timestamp'].replace('/', '-').replace(' ', 'T'))
            except Exception:
                return datetime.min

        events.sort(key=parse_ts)
        return events
