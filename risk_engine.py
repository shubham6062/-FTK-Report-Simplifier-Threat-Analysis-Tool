"""
risk_engine.py - Risk Scoring Engine
Calculates risk scores and threat levels based on forensic findings.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Calculates a numerical risk score from parsed forensic data
    and maps it to a human-readable threat level.

    Scoring formula:
        Deleted Files       → +5  per file
        Executable Files    → +10 per file
        Suspicious Keywords → +3  per keyword hit
        USB Activity        → +10 flat
        Known Malicious Domain → +20 per domain
    """

    # Score thresholds
    THRESHOLDS = {
        'LOW':      (0,   30),
        'MEDIUM':   (31,  60),
        'HIGH':     (61, 100),
        'CRITICAL': (101, float('inf')),
    }

    # Score weights
    WEIGHTS = {
        'deleted_file':       5,
        'executable_file':   10,
        'suspicious_keyword': 3,
        'usb_activity':      10,   # flat, not per-device
        'malicious_domain':  20,
        'hidden_file':        3,
        'archive_file':       2,
        'suspicious_file':    8,
    }

    LEVEL_COLORS = {
        'LOW':      '#2ecc71',
        'MEDIUM':   '#f39c12',
        'HIGH':     '#e74c3c',
        'CRITICAL': '#8e44ad',
    }

    LEVEL_ICONS = {
        'LOW':      '🟢',
        'MEDIUM':   '🟡',
        'HIGH':     '🔴',
        'CRITICAL': '🟣',
    }

    def __init__(self, parsed_data: dict, analysis_results: Optional[dict] = None):
        self.data = parsed_data
        self.analysis = analysis_results or {}
        self.score_breakdown = {}
        self.total_score = 0
        self.threat_level = 'LOW'

    def calculate(self) -> dict:
        """
        Run the full risk scoring calculation.

        Returns:
            dict: Score, threat level, breakdown, and gauge metadata
        """
        logger.info("Calculating risk score...")
        self.score_breakdown = {}
        self.total_score = 0

        self._score_deleted_files()
        self._score_executable_files()
        self._score_suspicious_keywords()
        self._score_usb_activity()
        self._score_malicious_domains()
        self._score_hidden_files()
        self._score_archive_files()
        self._score_suspicious_files()

        self.threat_level = self._determine_threat_level(self.total_score)

        return {
            'total_score': self.total_score,
            'threat_level': self.threat_level,
            'breakdown': self.score_breakdown,
            'color': self.LEVEL_COLORS[self.threat_level],
            'icon': self.LEVEL_ICONS[self.threat_level],
            'description': self._get_level_description(),
            'gauge_data': self._build_gauge_data(),
        }

    # ─── Scorers ──────────────────────────────────────────────────────────────

    def _score_deleted_files(self):
        count = len(self.data.get('deleted_files', []))
        points = count * self.WEIGHTS['deleted_file']
        self._add_score('Deleted Files', points, count, self.WEIGHTS['deleted_file'])

    def _score_executable_files(self):
        count = len(self.data.get('executable_files', []))
        points = count * self.WEIGHTS['executable_file']
        self._add_score('Executable Files', points, count, self.WEIGHTS['executable_file'])

    def _score_suspicious_keywords(self):
        hits = self.data.get('keyword_hits', [])
        total_occurrences = sum(h.get('count', 0) for h in hits)
        points = total_occurrences * self.WEIGHTS['suspicious_keyword']
        self._add_score('Suspicious Keywords', points, total_occurrences, self.WEIGHTS['suspicious_keyword'])

    def _score_usb_activity(self):
        usb_count = len(self.data.get('usb_activity', []))
        points = self.WEIGHTS['usb_activity'] if usb_count > 0 else 0
        self._add_score('USB Activity', points, usb_count, self.WEIGHTS['usb_activity'])

    def _score_malicious_domains(self):
        domain_analysis = self.analysis.get('domain_analysis', {})
        malicious = domain_analysis.get('malicious_domains', [])

        # Also pull from browser_history flagged as suspicious
        history = self.data.get('browser_history', [])
        suspicious_hist = [h for h in history if h.get('suspicious')]
        total = len(malicious) + len(suspicious_hist)

        points = len(malicious) * self.WEIGHTS['malicious_domain']
        self._add_score('Known Malicious Domains', points, total, self.WEIGHTS['malicious_domain'])

    def _score_hidden_files(self):
        count = len(self.data.get('hidden_files', []))
        points = count * self.WEIGHTS['hidden_file']
        self._add_score('Hidden Files', points, count, self.WEIGHTS['hidden_file'])

    def _score_archive_files(self):
        count = len(self.data.get('archive_files', []))
        points = count * self.WEIGHTS['archive_file']
        self._add_score('Archive Files', points, count, self.WEIGHTS['archive_file'])

    def _score_suspicious_files(self):
        count = len(self.data.get('suspicious_files', []))
        # Avoid double counting with executable_files
        exe_count = len(self.data.get('executable_files', []))
        extra = max(0, count - exe_count)
        points = extra * self.WEIGHTS['suspicious_file']
        self._add_score('Suspicious Non-Executable Files', points, extra, self.WEIGHTS['suspicious_file'])

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _add_score(self, category: str, points: int, count: int, weight: int):
        self.score_breakdown[category] = {
            'count': count,
            'weight': weight,
            'points': points,
        }
        self.total_score += points
        logger.debug(f"  {category}: {count} × {weight} = {points}")

    @classmethod
    def _determine_threat_level(cls, score: int) -> str:
        for level, (low, high) in cls.THRESHOLDS.items():
            if low <= score <= high:
                return level
        return 'CRITICAL'

    def _get_level_description(self) -> str:
        descs = {
            'LOW': (
                "No significant threats detected. The investigation found minimal risk indicators. "
                "Standard monitoring and routine procedures are recommended."
            ),
            'MEDIUM': (
                "Some suspicious activity detected. Several risk indicators require attention. "
                "Further investigation into the flagged items is recommended."
            ),
            'HIGH': (
                "Multiple threat indicators identified. Significant suspicious activity detected "
                "including suspicious files, deleted data, and/or malicious keywords. "
                "Immediate investigation is strongly recommended."
            ),
            'CRITICAL': (
                "CRITICAL THREAT LEVEL. Severe indicators of compromise detected, including known malicious "
                "domains, high-risk executables, and/or credential theft indicators. "
                "Escalate immediately and isolate the affected system."
            ),
        }
        return descs.get(self.threat_level, '')

    def _build_gauge_data(self) -> dict:
        """Build data for Plotly gauge chart."""
        return {
            'value': min(self.total_score, 150),
            'max': 150,
            'thresholds': [30, 60, 100, 150],
            'colors': ['#2ecc71', '#f39c12', '#e74c3c', '#8e44ad'],
            'labels': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        }
