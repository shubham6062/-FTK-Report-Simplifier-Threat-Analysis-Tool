"""
dashboard.py - Dashboard & Visualization Module
Generates Plotly charts for the Streamlit dashboard.
"""

import logging
from typing import Optional

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

logger = logging.getLogger(__name__)

# ─── Color Palette ────────────────────────────────────────────────────────────
COLORS = {
    'bg':       '#0f0f1a',
    'surface':  '#1a1a2e',
    'surface2': '#16213e',
    'accent':   '#0f3460',
    'text':     '#e0e0e0',
    'muted':    '#888888',
    'critical': '#8e44ad',
    'high':     '#e74c3c',
    'medium':   '#f39c12',
    'low':      '#2ecc71',
    'info':     '#3498db',
}

CHART_TEMPLATE = dict(
    paper_bgcolor=COLORS['surface'],
    plot_bgcolor=COLORS['surface2'],
    font=dict(color=COLORS['text'], family='Segoe UI, system-ui, sans-serif', size=12),
    margin=dict(l=20, r=20, t=40, b=20),
)


class DashboardCharts:
    """
    Produces all Plotly charts used in the Streamlit dashboard.
    Each method returns a Plotly Figure object ready for st.plotly_chart().
    """

    def __init__(self, parsed_data: dict, analysis_results: dict, risk_results: dict):
        self.data = parsed_data
        self.analysis = analysis_results
        self.risk = risk_results

    # ─── Public chart factory methods ─────────────────────────────────────────

    def risk_gauge(self) -> go.Figure:
        """Animated gauge chart showing risk score and threat level."""
        score = min(self.risk.get('total_score', 0), 150)
        level = self.risk.get('threat_level', 'LOW')
        color = self.risk.get('color', COLORS['low'])

        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            title={'text': f"Risk Score — <b>{level}</b>", 'font': {'color': COLORS['text'], 'size': 16}},
            number={'font': {'color': color, 'size': 40}},
            gauge={
                'axis': {
                    'range': [0, 150],
                    'tickwidth': 1,
                    'tickcolor': COLORS['muted'],
                    'tickvals': [0, 30, 60, 100, 150],
                    'ticktext': ['0', '30', '60', '100', '150+'],
                    'tickfont': {'color': COLORS['muted']},
                },
                'bar': {'color': color, 'thickness': 0.3},
                'bgcolor': COLORS['surface2'],
                'borderwidth': 0,
                'steps': [
                    {'range': [0,   30],  'color': '#1a3a2a'},
                    {'range': [30,  60],  'color': '#3a3010'},
                    {'range': [60,  100], 'color': '#3a1010'},
                    {'range': [100, 150], 'color': '#2a0a3a'},
                ],
                'threshold': {
                    'line': {'color': color, 'width': 4},
                    'thickness': 0.75,
                    'value': score,
                },
            }
        ))
        fig.update_layout(**CHART_TEMPLATE, height=280)
        return fig

    def file_type_pie(self) -> go.Figure:
        """Donut chart of file type distribution."""
        dist = self.analysis.get('file_type_distribution', {})
        categories = dist.get('categories', {})

        labels = [k for k, v in categories.items() if v > 0]
        values = [v for v in categories.values() if v > 0]

        if not values:
            return self._empty_chart("No file type data available")

        palette = [COLORS['info'], COLORS['high'], COLORS['medium'],
                   COLORS['low'], COLORS['critical'], COLORS['accent']]

        fig = go.Figure(go.Pie(
            labels=labels,
            values=values,
            hole=0.55,
            marker=dict(colors=palette[:len(labels)], line=dict(color=COLORS['bg'], width=2)),
            textinfo='percent+label',
            textfont=dict(color=COLORS['text'], size=11),
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>',
        ))
        fig.update_layout(
            **CHART_TEMPLATE,
            title=dict(text='File Type Distribution', font=dict(color=COLORS['text'])),
            showlegend=True,
            legend=dict(font=dict(color=COLORS['text'])),
            height=320,
        )
        return fig

    def keyword_bar(self) -> go.Figure:
        """Horizontal bar chart of keyword frequencies."""
        hits = self.data.get('keyword_hits', [])
        if not hits:
            return self._empty_chart("No keyword data available")

        df = pd.DataFrame(hits).sort_values('count', ascending=True)

        colors_list = []
        high_risk = {'hack', 'malware', 'credentials', 'password'}
        financial = {'bitcoin', 'crypto', 'wallet', 'bank'}
        for kw in df['keyword']:
            if kw in high_risk:
                colors_list.append(COLORS['high'])
            elif kw in financial:
                colors_list.append(COLORS['critical'])
            else:
                colors_list.append(COLORS['medium'])

        fig = go.Figure(go.Bar(
            x=df['count'],
            y=df['keyword'],
            orientation='h',
            marker=dict(color=colors_list, line=dict(width=0)),
            text=df['count'],
            textposition='outside',
            textfont=dict(color=COLORS['text'], size=11),
            hovertemplate='<b>%{y}</b><br>Count: %{x}<extra></extra>',
        ))
        fig.update_layout(
            **CHART_TEMPLATE,
            title=dict(text='Keyword Frequency', font=dict(color=COLORS['text'])),
            xaxis=dict(title='Occurrences', color=COLORS['muted'], gridcolor=COLORS['accent']),
            yaxis=dict(color=COLORS['muted'], tickfont=dict(size=11)),
            height=max(250, len(df) * 38 + 80),
        )
        return fig

    def timeline_scatter(self) -> go.Figure:
        """Scatter/bubble timeline of forensic events."""
        events = self.data.get('timeline', [])
        if not events:
            return self._empty_chart("No timeline events available")

        from datetime import datetime

        records = []
        for e in events:
            try:
                ts = datetime.fromisoformat(e['timestamp'].replace('/', '-').replace(' ', 'T'))
                records.append({'timestamp': ts, 'event_type': e['event_type'], 'desc': e['description'][:80]})
            except Exception:
                continue

        if not records:
            return self._empty_chart("Could not parse timeline timestamps")

        df = pd.DataFrame(records)
        event_colors = {
            'USB Device Activity': COLORS['critical'],
            'File Deletion': COLORS['high'],
            'File Creation': COLORS['low'],
            'File Modification': COLORS['medium'],
            'File Access': COLORS['info'],
            'Execution': COLORS['high'],
            'Browser Activity': COLORS['accent'],
            'Web Access': COLORS['info'],
            'Authentication': COLORS['medium'],
            'General Activity': COLORS['muted'],
        }

        fig = go.Figure()
        for etype, group in df.groupby('event_type'):
            fig.add_trace(go.Scatter(
                x=group['timestamp'],
                y=[etype] * len(group),
                mode='markers',
                name=etype,
                marker=dict(
                    color=event_colors.get(etype, COLORS['muted']),
                    size=12,
                    line=dict(width=1, color=COLORS['bg']),
                    symbol='circle',
                ),
                text=group['desc'],
                hovertemplate='<b>%{y}</b><br>Time: %{x}<br>%{text}<extra></extra>',
            ))

        fig.update_layout(
            **CHART_TEMPLATE,
            title=dict(text='Forensic Event Timeline', font=dict(color=COLORS['text'])),
            xaxis=dict(title='Timestamp', color=COLORS['muted'], gridcolor=COLORS['accent']),
            yaxis=dict(title='Event Type', color=COLORS['muted'], gridcolor=COLORS['accent']),
            legend=dict(font=dict(color=COLORS['text']), bgcolor=COLORS['surface']),
            height=400,
        )
        return fig

    def risk_breakdown_bar(self) -> go.Figure:
        """Stacked bar showing risk score contribution by category."""
        breakdown = self.risk.get('breakdown', {})
        if not breakdown:
            return self._empty_chart("No risk breakdown data")

        cats = list(breakdown.keys())
        points = [breakdown[c]['points'] for c in cats]

        palette = [COLORS['high'] if p >= 20 else COLORS['medium'] if p >= 5 else COLORS['low'] for p in points]

        fig = go.Figure(go.Bar(
            x=points,
            y=cats,
            orientation='h',
            marker=dict(color=palette, line=dict(width=0)),
            text=[f'+{p}' for p in points],
            textposition='outside',
            textfont=dict(color=COLORS['text']),
            hovertemplate='<b>%{y}</b><br>Points: %{x}<extra></extra>',
        ))
        fig.update_layout(
            **CHART_TEMPLATE,
            title=dict(text='Risk Score Contributions', font=dict(color=COLORS['text'])),
            xaxis=dict(title='Points', color=COLORS['muted'], gridcolor=COLORS['accent']),
            yaxis=dict(color=COLORS['muted']),
            height=max(250, len(cats) * 40 + 80),
        )
        return fig

    def domain_bar(self) -> go.Figure:
        """Bar chart of top visited domains."""
        domain_analysis = self.analysis.get('domain_analysis', {})
        top_domains = domain_analysis.get('top_domains', [])
        if not top_domains:
            return self._empty_chart("No domain data available")

        domains, counts = zip(*top_domains[:15]) if top_domains else ([], [])
        malicious_set = {d['domain'] for d in domain_analysis.get('malicious_domains', [])}
        suspicious_set = {d['domain'] for d in domain_analysis.get('suspicious_domains', [])}

        bar_colors = []
        for d in domains:
            if d in malicious_set:
                bar_colors.append(COLORS['critical'])
            elif d in suspicious_set:
                bar_colors.append(COLORS['high'])
            else:
                bar_colors.append(COLORS['info'])

        fig = go.Figure(go.Bar(
            x=list(counts),
            y=list(domains),
            orientation='h',
            marker=dict(color=bar_colors, line=dict(width=0)),
            text=list(counts),
            textposition='outside',
            textfont=dict(color=COLORS['text']),
            hovertemplate='<b>%{y}</b><br>Visits: %{x}<extra></extra>',
        ))
        fig.update_layout(
            **CHART_TEMPLATE,
            title=dict(text='Top Visited Domains', font=dict(color=COLORS['text'])),
            xaxis=dict(title='Visit Count', color=COLORS['muted'], gridcolor=COLORS['accent']),
            yaxis=dict(color=COLORS['muted'], autorange='reversed'),
            height=max(300, len(domains) * 32 + 80),
        )
        return fig

    def threat_indicators_chart(self) -> go.Figure:
        """Horizontal severity chart for threat indicators."""
        indicators = self.analysis.get('threat_indicators', [])
        if not indicators:
            return self._empty_chart("No threat indicators found")

        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        severity_colors = {
            'CRITICAL': COLORS['critical'],
            'HIGH': COLORS['high'],
            'MEDIUM': COLORS['medium'],
            'LOW': COLORS['low'],
        }

        sorted_ind = sorted(indicators, key=lambda i: severity_order.get(i['severity'], 0), reverse=True)

        types = [i['type'] for i in sorted_ind]
        severities = [i['severity'] for i in sorted_ind]
        details = [i['detail'] for i in sorted_ind]
        bar_colors = [severity_colors.get(s, COLORS['muted']) for s in severities]

        fig = go.Figure(go.Bar(
            x=[severity_order.get(s, 1) for s in severities],
            y=types,
            orientation='h',
            marker=dict(color=bar_colors, line=dict(width=0)),
            text=severities,
            textposition='inside',
            textfont=dict(color='white', size=11),
            customdata=details,
            hovertemplate='<b>%{y}</b><br>Severity: %{text}<br>%{customdata}<extra></extra>',
        ))
        fig.update_layout(
            **CHART_TEMPLATE,
            title=dict(text='Threat Indicators by Severity', font=dict(color=COLORS['text'])),
            xaxis=dict(title='Severity Level', tickvals=[1,2,3,4], ticktext=['LOW','MEDIUM','HIGH','CRITICAL'],
                       color=COLORS['muted'], gridcolor=COLORS['accent']),
            yaxis=dict(color=COLORS['muted']),
            height=max(280, len(indicators) * 45 + 80),
        )
        return fig

    def file_stats_bar(self) -> go.Figure:
        """Summary bar chart of file statistics."""
        stats = self.analysis.get('file_statistics', {})
        if not stats:
            return self._empty_chart("No file statistics available")

        labels = ['Total Files', 'Suspicious', 'Deleted', 'Hidden', 'Archives', 'Executables']
        values = [
            stats.get('total', 0),
            stats.get('suspicious', 0),
            stats.get('deleted', 0),
            stats.get('hidden', 0),
            stats.get('archives', 0),
            stats.get('executables', 0),
        ]
        bar_colors = [COLORS['info'], COLORS['high'], COLORS['medium'],
                      COLORS['muted'], COLORS['low'], COLORS['critical']]

        fig = go.Figure(go.Bar(
            x=labels,
            y=values,
            marker=dict(color=bar_colors, line=dict(width=0)),
            text=values,
            textposition='outside',
            textfont=dict(color=COLORS['text']),
            hovertemplate='<b>%{x}</b><br>Count: %{y}<extra></extra>',
        ))
        fig.update_layout(
            **CHART_TEMPLATE,
            title=dict(text='File Statistics Overview', font=dict(color=COLORS['text'])),
            yaxis=dict(title='Count', color=COLORS['muted'], gridcolor=COLORS['accent']),
            xaxis=dict(color=COLORS['muted']),
            height=300,
            showlegend=False,
        )
        return fig

    # ─── Utility ──────────────────────────────────────────────────────────────

    @staticmethod
    def _empty_chart(message: str) -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(
            text=message, xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(color=COLORS['muted'], size=14)
        )
        fig.update_layout(**CHART_TEMPLATE, height=200)
        return fig
