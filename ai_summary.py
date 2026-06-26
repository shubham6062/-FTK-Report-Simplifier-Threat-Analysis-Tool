"""
ai_summary.py - AI Summary Module
Generates human-readable investigation summaries using OpenAI API (if available)
or falls back to a rule-based summary engine.
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class AISummaryGenerator:
    """
    Generates plain-language investigation summaries for non-technical stakeholders.
    Uses OpenAI GPT if an API key is configured; otherwise uses the built-in
    rule-based summary engine.
    """

    def __init__(self, parsed_data: dict, analysis_results: dict, risk_results: dict,
                 api_key: Optional[str] = None):
        self.data = parsed_data
        self.analysis = analysis_results
        self.risk = risk_results
        self.api_key = api_key or os.environ.get('OPENAI_API_KEY', '')

    def generate(self) -> dict:
        """
        Generate a complete investigation summary.

        Returns:
            dict with keys: executive_summary, technical_summary, method_used
        """
        if self.api_key and self.api_key.startswith('sk-'):
            try:
                summary = self._generate_ai_summary()
                return {**summary, 'method_used': 'OpenAI GPT'}
            except Exception as e:
                logger.warning(f"OpenAI API failed ({e}), falling back to rule-based summary.")

        summary = self._generate_rule_based_summary()
        return {**summary, 'method_used': 'Rule-Based Engine'}

    # ─── OpenAI-powered summary ───────────────────────────────────────────────

    def _generate_ai_summary(self) -> dict:
        """Call OpenAI API to generate a polished summary."""
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("openai package not installed.")

        client = OpenAI(api_key=self.api_key)
        context = self._build_context_string()
        prompt = f"""You are a senior digital forensics analyst writing an investigation report for a non-technical client.

Based on the following forensic data, generate:
1. An EXECUTIVE SUMMARY (3-5 sentences, plain language, no jargon) for a business executive.
2. A TECHNICAL SUMMARY (5-8 sentences) for an IT security team.

Forensic Data:
{context}

Format your response exactly as:
EXECUTIVE SUMMARY:
[summary here]

TECHNICAL SUMMARY:
[summary here]"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.3
        )

        text = response.choices[0].message.content or ""
        return self._parse_ai_response(text)

    def _parse_ai_response(self, text: str) -> dict:
        """Parse OpenAI response into executive and technical summaries."""
        executive = ""
        technical = ""

        if "EXECUTIVE SUMMARY:" in text and "TECHNICAL SUMMARY:" in text:
            parts = text.split("TECHNICAL SUMMARY:")
            executive = parts[0].replace("EXECUTIVE SUMMARY:", "").strip()
            technical = parts[1].strip()
        else:
            executive = text[:600].strip()
            technical = text[600:].strip() if len(text) > 600 else executive

        return {
            'executive_summary': executive,
            'technical_summary': technical,
        }

    # ─── Rule-based summary ───────────────────────────────────────────────────

    def _generate_rule_based_summary(self) -> dict:
        """Build deterministic summaries from findings without AI."""
        stats = self.analysis.get('summary_stats', {})
        risk_level = self.risk.get('threat_level', 'UNKNOWN')
        risk_score = self.risk.get('total_score', 0)
        case_info = self.data.get('case_info', {})

        # Gather key facts
        total_files = stats.get('total_files', 0)
        deleted_files = stats.get('deleted_files', 0)
        suspicious_files = stats.get('suspicious_files', 0)
        usb_devices = stats.get('usb_devices', 0)
        keyword_hits = stats.get('unique_keywords', 0)
        malicious_domains = stats.get('malicious_domains', 0)
        total_urls = stats.get('total_urls', 0)
        timeline_events = stats.get('timeline_events', 0)
        indicators = self.analysis.get('threat_indicators', [])

        executive = self._build_executive_summary(
            case_info, total_files, deleted_files, suspicious_files,
            usb_devices, keyword_hits, malicious_domains, risk_level, risk_score
        )

        technical = self._build_technical_summary(
            total_files, deleted_files, suspicious_files, usb_devices,
            keyword_hits, malicious_domains, total_urls, timeline_events,
            indicators, risk_score, risk_level
        )

        return {
            'executive_summary': executive,
            'technical_summary': technical,
        }

    def _build_executive_summary(self, case_info, total_files, deleted_files,
                                  suspicious_files, usb_devices, keyword_hits,
                                  malicious_domains, risk_level, risk_score) -> str:
        parts = []
        case_name = case_info.get('case_name', 'this investigation')

        parts.append(
            f"This forensic investigation of case '{case_name}' has been completed "
            f"with an overall threat level of {risk_level} (Risk Score: {risk_score})."
        )

        if suspicious_files > 0 or deleted_files > 0:
            file_detail = []
            if suspicious_files > 0:
                file_detail.append(f"{suspicious_files} suspicious executable or script file(s)")
            if deleted_files > 0:
                file_detail.append(f"{deleted_files} deleted file(s)")
            parts.append(f"The analysis identified {' and '.join(file_detail)} that warrant further review.")

        if usb_devices > 0:
            parts.append(
                f"USB device activity was detected on this system, indicating external storage "
                f"devices were connected — this may indicate data transfer or exfiltration."
            )

        if keyword_hits > 0:
            parts.append(
                f"Sensitive keyword matches were found in the evidence, including terms related to "
                f"{'financial activity, ' if self._has_financial_keywords() else ''}"
                f"{'security threats, ' if self._has_security_keywords() else ''}"
                f"raising concerns that require attention."
            )

        if malicious_domains > 0:
            parts.append(
                f"Access to {malicious_domains} known malicious or suspicious domain(s) was detected — "
                f"this is a strong indicator of potential compromise."
            )

        # Closing recommendation
        if risk_level == 'CRITICAL':
            parts.append("Immediate escalation and system isolation is strongly recommended.")
        elif risk_level == 'HIGH':
            parts.append("Prompt investigation and remediation actions are strongly recommended.")
        elif risk_level == 'MEDIUM':
            parts.append("Further investigation of the flagged items is recommended.")
        else:
            parts.append("No immediate action required; continue standard monitoring.")

        return " ".join(parts)

    def _build_technical_summary(self, total_files, deleted_files, suspicious_files,
                                   usb_devices, keyword_hits, malicious_domains,
                                   total_urls, timeline_events, indicators,
                                   risk_score, risk_level) -> str:
        parts = []

        parts.append(
            f"Static forensic analysis processed {total_files} total file artifacts. "
            f"The risk scoring engine assigned a composite score of {risk_score}, "
            f"mapping to threat level: {risk_level}."
        )

        if suspicious_files > 0:
            susp = self.data.get('suspicious_files', [])
            ext_list = list({f.get('name','').split('.')[-1] for f in susp[:5]})
            parts.append(
                f"{suspicious_files} file(s) with high-risk extensions were identified "
                f"(types: {', '.join(ext_list)}). These require hash verification and AV scanning."
            )

        if deleted_files > 0:
            parts.append(
                f"{deleted_files} deleted file(s) were recovered from the recycle bin "
                f"or marked as deleted in the file system. File carving is recommended "
                f"to recover full content."
            )

        if usb_devices > 0:
            usb_list = self.data.get('usb_activity', [])
            parts.append(
                f"{usb_devices} USB device(s) were enumerated from registry artifacts. "
                f"Device names: {', '.join(d.get('device_name','Unknown') for d in usb_list[:3])}."
            )

        if total_urls > 0:
            parts.append(
                f"Browser history analysis extracted {total_urls} URL(s). "
                f"{malicious_domains} domain(s) matched known malicious or suspicious threat intelligence feeds."
            )

        if keyword_hits > 0:
            kw_list = [h['keyword'] for h in self.data.get('keyword_hits', [])[:5]]
            parts.append(
                f"Keyword scanning returned {keyword_hits} sensitive term match(es): "
                f"{', '.join(kw_list)}. Full context review of each occurrence is recommended."
            )

        if timeline_events > 0:
            parts.append(
                f"The forensic timeline contains {timeline_events} timestamped event(s). "
                f"Correlation of file access, deletion, and USB activity timestamps may reveal intent."
            )

        # Add indicator types
        indicator_types = [i['type'] for i in indicators if i.get('severity') in ('HIGH', 'CRITICAL')]
        if indicator_types:
            parts.append(
                f"Critical indicators requiring priority attention: {', '.join(indicator_types)}."
            )

        return " ".join(parts)

    def _build_context_string(self) -> str:
        """Build a compact context string for the AI prompt."""
        stats = self.analysis.get('summary_stats', {})
        risk = self.risk
        case = self.data.get('case_info', {})
        kw_hits = self.data.get('keyword_hits', [])
        usb = self.data.get('usb_activity', [])
        susp = self.data.get('suspicious_files', [])

        lines = [
            f"Case: {case.get('case_name', 'Unknown')}",
            f"Investigator: {case.get('investigator', 'Unknown')}",
            f"Risk Level: {risk.get('threat_level')} (Score: {risk.get('total_score')})",
            f"Total Files: {stats.get('total_files', 0)}",
            f"Suspicious Files: {stats.get('suspicious_files', 0)} — types: "
            f"{', '.join(set(f.get('name','').split('.')[-1] for f in susp[:5]))}",
            f"Deleted Files: {stats.get('deleted_files', 0)}",
            f"Hidden Files: {stats.get('hidden_files', 0)}",
            f"USB Devices: {stats.get('usb_devices', 0)} — "
            f"{', '.join(d.get('device_name','?') for d in usb[:3])}",
            f"Keywords Found: {stats.get('unique_keywords', 0)} — "
            f"{', '.join(h['keyword'] for h in kw_hits[:5])}",
            f"Total URLs: {stats.get('total_urls', 0)}",
            f"Malicious Domains: {stats.get('malicious_domains', 0)}",
            f"Timeline Events: {stats.get('timeline_events', 0)}",
        ]
        return "\n".join(lines)

    def _has_financial_keywords(self) -> bool:
        hits = {h['keyword'] for h in self.data.get('keyword_hits', [])}
        return bool(hits & {'bitcoin', 'crypto', 'wallet', 'bank'})

    def _has_security_keywords(self) -> bool:
        hits = {h['keyword'] for h in self.data.get('keyword_hits', [])}
        return bool(hits & {'password', 'credentials', 'hack', 'hacker', 'malware'})
