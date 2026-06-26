"""
analyzer.py - FTK Report Analyzer Module
Performs deep analysis on parsed forensic data including domain analysis,
file classification, and pattern detection.
"""

import re
import logging
from collections import Counter
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)


class ForensicAnalyzer:
    """
    Performs forensic analysis on parsed FTK report data.
    Generates insights, domain statistics, file type breakdowns,
    and threat indicators.
    """

    KNOWN_MALICIOUS_DOMAINS = {
        'darkweb.to', 'exploit.in', 'hackforums.net', 'nulled.to',
        'crimeamarket.com', 'raidforums.com', 'leakforums.net',
        'tor2web.org', 'onion.to', 'zerodayinitiative.com',
        'pastebin.com', 'paste.ee', 'ghostbin.com',
    }

    CLEAN_DOMAINS = {
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'github.com', 'stackoverflow.com', 'wikipedia.org',
        'youtube.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    }

    def __init__(self, parsed_data: dict):
        self.data = parsed_data
        self.results = {}

    def analyze(self) -> dict:
        """
        Run all analysis routines and return comprehensive results.

        Returns:
            dict: Analysis results with all computed insights
        """
        logger.info("Running forensic analysis...")
        self.results = {
            'file_type_distribution': self._analyze_file_types(),
            'domain_analysis': self._analyze_domains(),
            'keyword_summary': self._summarize_keywords(),
            'threat_indicators': self._identify_threat_indicators(),
            'file_statistics': self._compute_file_stats(),
            'top_keywords': self._get_top_keywords(),
            'suspicious_domain_list': self._get_suspicious_domains(),
            'recommendations': self._generate_recommendations(),
            'summary_stats': self._compute_summary_stats(),
        }
        return self.results

    # ─── Analysis methods ─────────────────────────────────────────────────────

    def _analyze_file_types(self) -> dict:
        """Categorize files by type and compute distribution."""
        categories = {
            'Executable': 0,
            'Document': 0,
            'Archive': 0,
            'Image': 0,
            'Script': 0,
            'Other': 0
        }

        ext_map = {
            '.exe': 'Executable', '.dll': 'Executable',
            '.bat': 'Script', '.ps1': 'Script', '.vbs': 'Script',
            '.sh': 'Script', '.cmd': 'Script',
            '.doc': 'Document', '.docx': 'Document',
            '.xls': 'Document', '.xlsx': 'Document',
            '.pdf': 'Document', '.txt': 'Document',
            '.ppt': 'Document', '.pptx': 'Document',
            '.zip': 'Archive', '.rar': 'Archive',
            '.7z': 'Archive', '.tar': 'Archive',
            '.gz': 'Archive', '.bz2': 'Archive',
            '.jpg': 'Image', '.jpeg': 'Image',
            '.png': 'Image', '.gif': 'Image',
            '.bmp': 'Image', '.tiff': 'Image',
        }

        ext_counter = Counter()
        for f in self.data.get('file_listings', []):
            ext = self._get_ext(f.get('name', ''))
            ext_counter[ext] += 1
            category = ext_map.get(ext, 'Other')
            categories[category] += 1

        return {
            'categories': categories,
            'extension_counts': dict(ext_counter.most_common(20))
        }

    def _analyze_domains(self) -> dict:
        """Analyze browser history domains for threat assessment."""
        history = self.data.get('browser_history', [])
        domain_counts = Counter()
        malicious = []
        suspicious = []

        for entry in history:
            domain = entry.get('domain', '').lower()
            if not domain:
                continue
            domain_counts[domain] += 1

            # Check against known malicious
            clean_domain = re.sub(r'^www\.', '', domain)
            if clean_domain in self.KNOWN_MALICIOUS_DOMAINS:
                malicious.append({'domain': domain, 'url': entry.get('url', ''), 'reason': 'Known malicious domain'})
            elif entry.get('suspicious') or any(
                kw in domain for kw in ['hack', 'crack', 'exploit', 'payload', 'c2', 'botnet']
            ):
                suspicious.append({'domain': domain, 'url': entry.get('url', ''), 'reason': 'Suspicious domain name'})

        return {
            'total_urls': len(history),
            'unique_domains': len(domain_counts),
            'top_domains': domain_counts.most_common(10),
            'malicious_domains': malicious,
            'suspicious_domains': suspicious,
        }

    def _summarize_keywords(self) -> dict:
        """Summarize keyword hits by category."""
        hits = self.data.get('keyword_hits', [])
        financial = ['bitcoin', 'crypto', 'wallet', 'bank']
        security = ['password', 'credentials', 'hack', 'hacker', 'malware']
        sensitive = ['confidential']

        summary = {
            'total_keywords_found': len(hits),
            'total_occurrences': sum(h.get('count', 0) for h in hits),
            'financial_keywords': [h for h in hits if h['keyword'] in financial],
            'security_keywords': [h for h in hits if h['keyword'] in security],
            'sensitive_keywords': [h for h in hits if h['keyword'] in sensitive],
        }
        return summary

    def _identify_threat_indicators(self) -> list:
        """Generate a list of concrete threat indicators found."""
        indicators = []

        # Suspicious files
        susp_files = self.data.get('suspicious_files', [])
        if susp_files:
            indicators.append({
                'type': 'Suspicious Files',
                'severity': 'HIGH',
                'detail': f"{len(susp_files)} suspicious executable/script file(s) detected",
                'items': [f['name'] for f in susp_files[:10]]
            })

        # Deleted files
        del_files = self.data.get('deleted_files', [])
        if del_files:
            indicators.append({
                'type': 'Deleted Files',
                'severity': 'MEDIUM',
                'detail': f"{len(del_files)} deleted file(s) found in recycle bin or marked deleted",
                'items': [f['name'] for f in del_files[:10]]
            })

        # USB activity
        usb = self.data.get('usb_activity', [])
        if usb:
            indicators.append({
                'type': 'USB Activity',
                'severity': 'MEDIUM',
                'detail': f"{len(usb)} USB device(s) connected to this system",
                'items': [d['device_name'] for d in usb]
            })

        # Malicious domains
        domain_analysis = self._analyze_domains()
        mal_domains = domain_analysis.get('malicious_domains', [])
        if mal_domains:
            indicators.append({
                'type': 'Malicious Domains',
                'severity': 'CRITICAL',
                'detail': f"Access to {len(mal_domains)} known malicious domain(s) detected",
                'items': [d['domain'] for d in mal_domains]
            })

        # High-risk keywords
        kw_hits = self.data.get('keyword_hits', [])
        high_risk_kw = [h for h in kw_hits if h['keyword'] in ['hack', 'malware', 'credentials']]
        if high_risk_kw:
            indicators.append({
                'type': 'High-Risk Keywords',
                'severity': 'HIGH',
                'detail': f"{len(high_risk_kw)} high-risk keyword(s) found in evidence",
                'items': [f"{h['keyword']} ({h['count']} occurrences)" for h in high_risk_kw]
            })

        # Archive files (potential data exfiltration)
        archives = self.data.get('archive_files', [])
        if archives:
            indicators.append({
                'type': 'Archive Files',
                'severity': 'MEDIUM',
                'detail': f"{len(archives)} archive file(s) found — possible data exfiltration vector",
                'items': [f['name'] for f in archives[:10]]
            })

        return indicators

    def _compute_file_stats(self) -> dict:
        """Compute file counts across categories."""
        return {
            'total': self.data.get('total_files', 0),
            'suspicious': len(self.data.get('suspicious_files', [])),
            'deleted': len(self.data.get('deleted_files', [])),
            'hidden': len(self.data.get('hidden_files', [])),
            'archives': len(self.data.get('archive_files', [])),
            'executables': len(self.data.get('executable_files', [])),
        }

    def _get_top_keywords(self) -> list:
        """Return top keywords sorted by occurrence count."""
        hits = self.data.get('keyword_hits', [])
        return sorted(hits, key=lambda x: x.get('count', 0), reverse=True)[:10]

    def _get_suspicious_domains(self) -> list:
        """Return all suspicious/malicious domains."""
        domain_analysis = self._analyze_domains()
        return domain_analysis.get('malicious_domains', []) + domain_analysis.get('suspicious_domains', [])

    def _generate_recommendations(self) -> list:
        """Generate actionable recommendations based on findings."""
        recs = []

        if self.data.get('suspicious_files'):
            recs.append({
                'priority': 'HIGH',
                'action': 'Investigate Suspicious Executables',
                'detail': 'Perform static and dynamic analysis on flagged .exe, .dll, .bat, .ps1, .vbs, .scr, .jar files. '
                          'Check file hashes against VirusTotal and other threat intelligence databases.'
            })

        if self.data.get('deleted_files'):
            recs.append({
                'priority': 'HIGH',
                'action': 'Review Deleted Files',
                'detail': 'Recover and examine deleted files. Deliberate deletion may indicate evidence tampering '
                          'or attempts to hide malicious activity.'
            })

        if self.data.get('browser_history'):
            recs.append({
                'priority': 'MEDIUM',
                'action': 'Analyze Browser History',
                'detail': 'Review full browser history including cached pages, cookies, and download history. '
                          'Correlate website visits with the timeline of suspicious events.'
            })

        if self.data.get('usb_activity'):
            recs.append({
                'priority': 'HIGH',
                'action': 'Examine USB Device Activity',
                'detail': 'Investigate all USB devices connected to the system. Check for data transfer logs, '
                          'file timestamps coinciding with USB connection times, and device identifiers.'
            })

        kw_hits = self.data.get('keyword_hits', [])
        if any(h['keyword'] in ['bitcoin', 'wallet', 'crypto'] for h in kw_hits):
            recs.append({
                'priority': 'HIGH',
                'action': 'Investigate Cryptocurrency Activity',
                'detail': 'Financial keywords (bitcoin, wallet, crypto) detected. Investigate cryptocurrency '
                          'wallets, transaction records, and potential ransomware activity.'
            })

        if any(h['keyword'] == 'credentials' for h in kw_hits):
            recs.append({
                'priority': 'CRITICAL',
                'action': 'Secure Compromised Credentials',
                'detail': 'Credential-related content detected. Immediately audit all accounts associated '
                          'with this device, enforce password resets, and review authentication logs.'
            })

        suspicious_domains = self._get_suspicious_domains()
        if suspicious_domains:
            recs.append({
                'priority': 'CRITICAL',
                'action': 'Block Malicious Domains',
                'detail': f"Block {len(suspicious_domains)} suspicious domain(s) at the network perimeter. "
                          f"Review network logs for data exfiltration to these domains."
            })

        if self.data.get('archive_files'):
            recs.append({
                'priority': 'MEDIUM',
                'action': 'Inspect Archive Files',
                'detail': 'Extract and scan all archive files for malicious content or exfiltrated data.'
            })

        if not recs:
            recs.append({
                'priority': 'LOW',
                'action': 'Standard Monitoring',
                'detail': 'No immediate high-risk indicators found. Maintain standard monitoring protocols '
                          'and periodic review of system logs.'
            })

        return recs

    def _compute_summary_stats(self) -> dict:
        """Top-level summary for executive dashboard."""
        stats = self._compute_file_stats()
        kw_summary = self._summarize_keywords()
        domain_analysis = self._analyze_domains()

        return {
            'total_files': stats['total'],
            'suspicious_files': stats['suspicious'],
            'deleted_files': stats['deleted'],
            'hidden_files': stats['hidden'],
            'total_keyword_hits': kw_summary['total_occurrences'],
            'unique_keywords': kw_summary['total_keywords_found'],
            'total_urls': domain_analysis['total_urls'],
            'malicious_domains': len(domain_analysis['malicious_domains']),
            'usb_devices': len(self.data.get('usb_activity', [])),
            'timeline_events': len(self.data.get('timeline', [])),
        }

    # ─── Utility ──────────────────────────────────────────────────────────────

    @staticmethod
    def _get_ext(filename: str) -> str:
        """Safely extract lowercase file extension."""
        try:
            import os
            return os.path.splitext(filename)[1].lower()
        except Exception:
            return ''
