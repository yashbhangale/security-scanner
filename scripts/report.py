#!/usr/bin/env python3
"""
Security Scanner - Report Generator

Aggregates results from all security scanners and generates
a comprehensive HTML dashboard report.

Usage:
    python3 report.py --reports-dir reports --template templates/report.html --output reports/report.html
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def load_json(filepath):
    """Safely load a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def parse_profile(reports_dir):
    """Parse the project profile."""
    data = load_json(os.path.join(reports_dir, 'profile.json'))
    if not data:
        return {
            'repository': 'Unknown',
            'branch': 'unknown',
            'commit': 'unknown',
            'languages': [],
            'technologies': [],
            'scanners': []
        }
    return data


def parse_trivy(reports_dir):
    """Parse Trivy scan results."""
    data = load_json(os.path.join(reports_dir, 'trivy', 'trivy-report.json'))
    result = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'findings': []}

    if not data:
        return result

    results = data.get('Results', [])
    for r in results:
        for vuln in r.get('Vulnerabilities', []):
            sev = vuln.get('Severity', 'UNKNOWN').lower()
            if sev == 'critical':
                result['critical'] += 1
            elif sev == 'high':
                result['high'] += 1
            elif sev == 'medium':
                result['medium'] += 1
            elif sev == 'low':
                result['low'] += 1
            result['findings'].append({
                'scanner': 'Trivy',
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'title': vuln.get('VulnerabilityID', 'N/A'),
                'description': vuln.get('Title', vuln.get('Description', 'N/A'))[:100],
                'target': r.get('Target', 'N/A')
            })

        for secret in r.get('Secrets', []):
            result['high'] += 1
            result['findings'].append({
                'scanner': 'Trivy',
                'severity': 'HIGH',
                'title': 'Secret Detected',
                'description': secret.get('Title', 'Hardcoded secret found'),
                'target': r.get('Target', 'N/A')
            })

        for misconfig in r.get('Misconfigurations', []):
            sev = misconfig.get('Severity', 'UNKNOWN').lower()
            if sev == 'critical':
                result['critical'] += 1
            elif sev == 'high':
                result['high'] += 1
            elif sev == 'medium':
                result['medium'] += 1
            elif sev == 'low':
                result['low'] += 1
            result['findings'].append({
                'scanner': 'Trivy',
                'severity': misconfig.get('Severity', 'UNKNOWN'),
                'title': misconfig.get('ID', 'N/A'),
                'description': misconfig.get('Title', 'N/A')[:100],
                'target': r.get('Target', 'N/A')
            })

    return result


def parse_gitleaks(reports_dir):
    """Parse Gitleaks scan results."""
    data = load_json(os.path.join(reports_dir, 'gitleaks', 'gitleaks.json'))
    result = {'secrets_found': 0, 'findings': []}

    if not data or not isinstance(data, list):
        return result

    result['secrets_found'] = len(data)
    for leak in data[:20]:  # Limit to top 20
        result['findings'].append({
            'scanner': 'Gitleaks',
            'severity': 'HIGH',
            'title': leak.get('RuleID', 'Secret'),
            'description': f"Secret in {leak.get('File', 'unknown')}:{leak.get('StartLine', '?')}",
            'target': leak.get('File', 'N/A')
        })

    return result


def parse_semgrep(reports_dir):
    """Parse Semgrep scan results."""
    data = load_json(os.path.join(reports_dir, 'semgrep', 'semgrep.json'))
    result = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'findings': []}

    if not data:
        return result

    results = data.get('results', [])
    for r in results:
        sev = r.get('extra', {}).get('severity', 'WARNING').upper()
        if sev == 'ERROR':
            result['high'] += 1
            mapped_sev = 'HIGH'
        elif sev == 'WARNING':
            result['medium'] += 1
            mapped_sev = 'MEDIUM'
        else:
            result['low'] += 1
            mapped_sev = 'LOW'

        result['findings'].append({
            'scanner': 'Semgrep',
            'severity': mapped_sev,
            'title': r.get('check_id', 'N/A').split('.')[-1],
            'description': r.get('extra', {}).get('message', 'N/A')[:100],
            'target': f"{r.get('path', 'N/A')}:{r.get('start', {}).get('line', '?')}"
        })

    return result


def parse_grype(reports_dir):
    """Parse Grype scan results."""
    data = load_json(os.path.join(reports_dir, 'grype', 'grype.json'))
    result = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'findings': []}

    if not data:
        return result

    matches = data.get('matches', [])
    for m in matches:
        vuln = m.get('vulnerability', {})
        sev = vuln.get('severity', 'Unknown').lower()
        if sev == 'critical':
            result['critical'] += 1
        elif sev == 'high':
            result['high'] += 1
        elif sev == 'medium':
            result['medium'] += 1
        elif sev == 'low':
            result['low'] += 1

        artifact = m.get('artifact', {})
        result['findings'].append({
            'scanner': 'Grype',
            'severity': vuln.get('severity', 'Unknown').upper(),
            'title': vuln.get('id', 'N/A'),
            'description': f"{artifact.get('name', '?')}@{artifact.get('version', '?')}",
            'target': artifact.get('name', 'N/A')
        })

    return result


def parse_checkov(reports_dir):
    """Parse Checkov scan results."""
    data = load_json(os.path.join(reports_dir, 'checkov', 'checkov.json'))
    result = {'passed': 0, 'failed': 0, 'skipped': 0, 'findings': []}

    if not data:
        return result

    checks = data if isinstance(data, list) else [data]
    for check_group in checks:
        summary = check_group.get('summary', {})
        result['passed'] += summary.get('passed', 0)
        result['failed'] += summary.get('failed', 0)
        result['skipped'] += summary.get('skipped', 0)

        failed_checks = check_group.get('results', {}).get('failed_checks', [])
        for fc in failed_checks[:20]:
            result['findings'].append({
                'scanner': 'Checkov',
                'severity': 'MEDIUM',
                'title': fc.get('check_id', 'N/A'),
                'description': fc.get('check_result', {}).get('evaluated_keys', [''])[0][:100] if fc.get('check_result', {}).get('evaluated_keys') else fc.get('name', 'N/A')[:100],
                'target': fc.get('file_path', 'N/A')
            })

    return result


def parse_hadolint(reports_dir):
    """Parse Hadolint scan results."""
    data = load_json(os.path.join(reports_dir, 'hadolint', 'hadolint.json'))
    result = {'issues': 0, 'findings': []}

    if not data or not isinstance(data, list):
        return result

    result['issues'] = len(data)
    for item in data[:20]:
        sev = item.get('level', 'warning').upper()
        if sev == 'ERROR':
            mapped_sev = 'HIGH'
        elif sev == 'WARNING':
            mapped_sev = 'MEDIUM'
        else:
            mapped_sev = 'LOW'

        result['findings'].append({
            'scanner': 'Hadolint',
            'severity': mapped_sev,
            'title': item.get('code', 'N/A'),
            'description': item.get('message', 'N/A')[:100],
            'target': item.get('file', 'Dockerfile')
        })

    return result


def parse_kube_linter(reports_dir):
    """Parse kube-linter scan results."""
    data = load_json(os.path.join(reports_dir, 'kube-linter', 'kube-linter.json'))
    result = {'issues': 0, 'findings': []}

    if not data:
        return result

    reports = data.get('Reports', [])
    result['issues'] = len(reports)
    for r in reports[:20]:
        result['findings'].append({
            'scanner': 'kube-linter',
            'severity': 'MEDIUM',
            'title': r.get('Check', 'N/A'),
            'description': r.get('Diagnostic', {}).get('Message', 'N/A')[:100],
            'target': r.get('Object', {}).get('K8sObject', {}).get('Name', 'N/A')
        })

    return result


def parse_syft(reports_dir):
    """Parse Syft SBOM results."""
    data = load_json(os.path.join(reports_dir, 'syft', 'sbom-cyclonedx.json'))
    result = {'components': 0}

    if not data:
        return result

    result['components'] = len(data.get('components', []))
    return result


def parse_sonar(reports_dir):
    """Parse SonarQube results."""
    measures_data = load_json(os.path.join(reports_dir, 'sonar', 'sonar-measures.json'))
    qg_data = load_json(os.path.join(reports_dir, 'sonar', 'sonar-quality-gate.json'))
    result = {'bugs': 0, 'vulnerabilities': 0, 'code_smells': 0, 'hotspots': 0, 'quality_gate': 'N/A'}

    if measures_data:
        measures = measures_data.get('component', {}).get('measures', [])
        for m in measures:
            metric = m.get('metric', '')
            value = m.get('value', '0')
            if metric == 'bugs':
                result['bugs'] = int(value)
            elif metric == 'vulnerabilities':
                result['vulnerabilities'] = int(value)
            elif metric == 'code_smells':
                result['code_smells'] = int(value)
            elif metric == 'security_hotspots':
                result['hotspots'] = int(value)

    if qg_data:
        status = qg_data.get('projectStatus', {}).get('status', 'N/A')
        result['quality_gate'] = status

    return result


def calculate_score(trivy, gitleaks, semgrep, grype, checkov, hadolint, kube_linter):
    """Calculate a security score from 0-100."""
    score = 100

    # Critical issues (-10 each, max -40)
    critical_total = trivy['critical'] + grype['critical']
    score -= min(critical_total * 10, 40)

    # High issues (-5 each, max -30)
    high_total = trivy['high'] + grype['high'] + semgrep['high'] + gitleaks['secrets_found']
    score -= min(high_total * 5, 30)

    # Medium issues (-2 each, max -20)
    medium_total = trivy['medium'] + grype['medium'] + semgrep['medium'] + checkov['failed']
    score -= min(medium_total * 2, 20)

    # Low issues (-1 each, max -10)
    low_total = trivy['low'] + grype['low'] + semgrep['low']
    score -= min(low_total, 10)

    # Docker and K8s issues
    score -= min(hadolint['issues'] * 2, 10)
    score -= min(kube_linter['issues'] * 2, 10)

    return max(0, score)


def build_scanner_card(title, status, rows):
    """Build an HTML scanner card with inline styles."""
    status_colors = {
        'pass': ('#1b5e20', '#66bb6a'),
        'warn': ('#e65100', '#ffa726'),
        'fail': ('#b71c1c', '#ef5350'),
        'skipped': ('#37474f', '#90a4ae')
    }
    bg_color, text_color = status_colors.get(status, ('#37474f', '#90a4ae'))
    status_label = status.upper()

    rows_html = ''
    for label, value in rows:
        rows_html += f'<tr><td style="padding:8px 12px;border-bottom:1px solid #1f4068;color:#90a4ae;">{label}</td><td style="padding:8px 12px;border-bottom:1px solid #1f4068;text-align:right;font-weight:600;color:#e0e0e0;">{value}</td></tr>\n'

    return f'''
    <div style="background:#16213e;border:1px solid #1f4068;border-radius:10px;padding:20px;margin-bottom:16px;display:inline-block;width:48%;vertical-align:top;margin-right:2%;">
        <h3 style="margin:0 0 14px;color:#e0e0e0;font-size:1rem;">{title}
            <span style="display:inline-block;padding:3px 10px;border-radius:4px;font-size:0.7rem;font-weight:700;background:{bg_color};color:{text_color};margin-left:8px;vertical-align:middle;">{status_label}</span>
        </h3>
        <table style="width:100%;border-collapse:collapse;">
            {rows_html}
        </table>
    </div>
    '''


def build_findings_table(all_findings):
    """Build the top findings HTML table with inline styles."""
    if not all_findings:
        return '<p style="color:#90a4ae;font-style:italic;padding:10px 0;">No findings to display.</p>'

    # Sort by severity: Critical > High > Medium > Low
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_findings = sorted(
        all_findings,
        key=lambda x: severity_order.get(x['severity'].upper(), 4)
    )[:30]  # Top 30 findings

    badge_styles = {
        'CRITICAL': 'background:#b71c1c;color:#ef5350;',
        'HIGH': 'background:#e65100;color:#ffa726;',
        'MEDIUM': 'background:#f57f17;color:#ffc107;',
        'LOW': 'background:#0d47a1;color:#4fc3f7;'
    }

    rows = ''
    for f in sorted_findings:
        sev = f['severity'].upper()
        badge_style = badge_styles.get(sev, badge_styles['LOW'])

        rows += f'''<tr>
            <td style="padding:10px 12px;border-bottom:1px solid #1f4068;"><span style="display:inline-block;padding:3px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;{badge_style}">{sev}</span></td>
            <td style="padding:10px 12px;border-bottom:1px solid #1f4068;color:#e0e0e0;">{f['scanner']}</td>
            <td style="padding:10px 12px;border-bottom:1px solid #1f4068;color:#4fc3f7;font-family:monospace;font-size:0.85rem;">{f['title']}</td>
            <td style="padding:10px 12px;border-bottom:1px solid #1f4068;color:#b0bec5;font-size:0.85rem;">{f['description']}</td>
            <td style="padding:10px 12px;border-bottom:1px solid #1f4068;color:#78909c;font-size:0.85rem;">{f['target']}</td>
        </tr>\n'''

    return f'''
    <table style="width:100%;border-collapse:collapse;font-size:0.9rem;background:#16213e;border:1px solid #1f4068;border-radius:8px;">
        <thead>
            <tr>
                <th style="background:#0f3460;padding:12px;text-align:left;font-weight:600;color:#4fc3f7;border-bottom:2px solid #1f4068;">Severity</th>
                <th style="background:#0f3460;padding:12px;text-align:left;font-weight:600;color:#4fc3f7;border-bottom:2px solid #1f4068;">Scanner</th>
                <th style="background:#0f3460;padding:12px;text-align:left;font-weight:600;color:#4fc3f7;border-bottom:2px solid #1f4068;">ID</th>
                <th style="background:#0f3460;padding:12px;text-align:left;font-weight:600;color:#4fc3f7;border-bottom:2px solid #1f4068;">Description</th>
                <th style="background:#0f3460;padding:12px;text-align:left;font-weight:600;color:#4fc3f7;border-bottom:2px solid #1f4068;">Target</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    '''


def build_download_links(reports_dir):
    """Build download links for available reports."""
    links = []
    report_files = [
        ('trivy/trivy-report.json', 'Trivy JSON'),
        ('trivy/sbom.json', 'Trivy SBOM'),
        ('gitleaks/gitleaks.json', 'Gitleaks JSON'),
        ('semgrep/semgrep.json', 'Semgrep JSON'),
        ('semgrep/semgrep.sarif', 'Semgrep SARIF'),
        ('syft/sbom-cyclonedx.json', 'SBOM CycloneDX'),
        ('syft/sbom-spdx.json', 'SBOM SPDX'),
        ('grype/grype.json', 'Grype JSON'),
        ('checkov/checkov.json', 'Checkov JSON'),
        ('checkov/checkov.sarif', 'Checkov SARIF'),
        ('hadolint/hadolint.json', 'Hadolint JSON'),
        ('kube-linter/kube-linter.json', 'kube-linter JSON'),
    ]

    for filepath, label in report_files:
        full_path = os.path.join(reports_dir, filepath)
        if os.path.exists(full_path):
            links.append(f'<a href="{filepath}" style="display:inline-block;margin:6px 10px;padding:10px 20px;background:#0f3460;color:#4fc3f7;border-radius:6px;text-decoration:none;font-size:0.9rem;border:1px solid #1f4068;">{label}</a>')

    if not links:
        return '<p style="color:#90a4ae;font-style:italic;">No report files available for download.</p>'

    return '\n'.join(links)


def build_standalone_report(profile, score, score_color, critical, high, medium, low,
                            trivy, gitleaks, semgrep, sonar, syft, grype, checkov, hadolint, kube_linter,
                            all_findings, scanners_run, reports_dir):
    """Build a fully standalone HTML report with embedded CSS and JS."""

    git_info = profile.get('git', {})
    repo = profile.get('repository', 'Unknown')
    branch = git_info.get('branch', 'unknown')
    commit = git_info.get('commit', 'unknown')
    languages = ', '.join(profile.get('languages', [])) or 'N/A'
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Build scanner data for JS
    scanners_data = []

    def add_scanner(name, status, metrics):
        scanners_data.append({'name': name, 'status': status, 'metrics': metrics})

    # Trivy
    trivy_total = trivy['critical'] + trivy['high'] + trivy['medium'] + trivy['low']
    t_status = 'fail' if trivy['critical'] > 0 else ('warn' if trivy['high'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'trivy', 'trivy-report.json')):
        t_status = 'skipped'
    add_scanner('Trivy - Vulnerability Scan', t_status,
                [('Critical', trivy['critical']), ('High', trivy['high']), ('Medium', trivy['medium']), ('Low', trivy['low']), ('Total', trivy_total)])

    # Gitleaks
    gl_status = 'fail' if gitleaks['secrets_found'] > 0 else 'pass'
    if not os.path.exists(os.path.join(reports_dir, 'gitleaks', 'gitleaks.json')):
        gl_status = 'skipped'
    add_scanner('Gitleaks - Secret Detection', gl_status, [('Secrets Found', gitleaks['secrets_found'])])

    # Semgrep
    semgrep_total = semgrep['high'] + semgrep['medium'] + semgrep['low']
    sg_status = 'fail' if semgrep['high'] > 0 else ('warn' if semgrep['medium'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'semgrep', 'semgrep.json')):
        sg_status = 'skipped'
    add_scanner('Semgrep - Static Analysis', sg_status,
                [('High', semgrep['high']), ('Medium', semgrep['medium']), ('Low', semgrep['low']), ('Total', semgrep_total)])

    # SonarQube
    sq_status = 'pass'
    if sonar['vulnerabilities'] > 0 or sonar['bugs'] > 5:
        sq_status = 'fail'
    elif sonar['code_smells'] > 10:
        sq_status = 'warn'
    if not os.path.exists(os.path.join(reports_dir, 'sonar', 'sonar-measures.json')):
        sq_status = 'skipped'
    add_scanner('SonarQube - Code Quality', sq_status,
                [('Bugs', sonar['bugs']), ('Vulnerabilities', sonar['vulnerabilities']), ('Code Smells', sonar['code_smells']), ('Hotspots', sonar['hotspots']), ('Quality Gate', sonar['quality_gate'])])

    # Syft
    sy_status = 'pass' if syft['components'] > 0 else 'skipped'
    if not os.path.exists(os.path.join(reports_dir, 'syft', 'sbom-cyclonedx.json')):
        sy_status = 'skipped'
    add_scanner('Syft - SBOM Generation', sy_status, [('Components', syft['components'])])

    # Grype
    grype_total = grype['critical'] + grype['high'] + grype['medium'] + grype['low']
    gr_status = 'fail' if grype['critical'] > 0 else ('warn' if grype['high'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'grype', 'grype.json')):
        gr_status = 'skipped'
    add_scanner('Grype - Dependency Scan', gr_status,
                [('Critical', grype['critical']), ('High', grype['high']), ('Medium', grype['medium']), ('Low', grype['low']), ('Total', grype_total)])

    # Checkov
    ck_status = 'fail' if checkov['failed'] > 5 else ('warn' if checkov['failed'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'checkov', 'checkov.json')):
        ck_status = 'skipped'
    add_scanner('Checkov - IaC Security', ck_status,
                [('Passed', checkov['passed']), ('Failed', checkov['failed']), ('Skipped', checkov['skipped'])])

    # Hadolint
    hl_status = 'warn' if hadolint['issues'] > 0 else 'pass'
    if not os.path.exists(os.path.join(reports_dir, 'hadolint', 'hadolint.json')):
        hl_status = 'skipped'
    add_scanner('Hadolint - Dockerfile Lint', hl_status, [('Issues', hadolint['issues'])])

    # kube-linter
    kl_status = 'warn' if kube_linter['issues'] > 0 else 'pass'
    if not os.path.exists(os.path.join(reports_dir, 'kube-linter', 'kube-linter.json')):
        kl_status = 'skipped'
    add_scanner('kube-linter - Kubernetes', kl_status, [('Issues', kube_linter['issues'])])

    # Build scanner cards HTML
    scanner_cards_html = ''
    for s in scanners_data:
        status_colors = {'pass': '#66bb6a', 'warn': '#ffa726', 'fail': '#ef5350', 'skipped': '#78909c'}
        status_bg = {'pass': '#1b5e20', 'warn': '#e65100', 'fail': '#b71c1c', 'skipped': '#37474f'}
        color = status_colors.get(s['status'], '#78909c')
        bg = status_bg.get(s['status'], '#37474f')
        metrics_html = ''
        for label, val in s['metrics']:
            metrics_html += f'<div class="metric-row"><span class="metric-label">{label}</span><span class="metric-value">{val}</span></div>'
        scanner_cards_html += f'''
        <div class="scanner-card">
            <div class="scanner-header">
                <span class="scanner-title">{s['name']}</span>
                <span class="status-badge" style="background:{bg};color:{color};">{s['status'].upper()}</span>
            </div>
            <div class="scanner-body">{metrics_html}</div>
        </div>'''

    # Build findings rows
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_findings = sorted(all_findings, key=lambda x: severity_order.get(x['severity'].upper(), 4))[:50]

    findings_rows = ''
    for f in sorted_findings:
        sev = f['severity'].upper()
        findings_rows += f'''
        <tr>
            <td><span class="sev-badge sev-{sev.lower()}">{sev}</span></td>
            <td>{f['scanner']}</td>
            <td class="mono">{f['title']}</td>
            <td class="desc">{f['description']}</td>
            <td class="target">{f['target']}</td>
        </tr>'''

    # Build the full HTML
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {repo}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 24px; }}

        /* Header */
        .header {{
            text-align: center;
            padding: 50px 30px;
            background: linear-gradient(135deg, #161b22 0%, #0d1117 50%, #161b22 100%);
            border: 1px solid #30363d;
            border-radius: 16px;
            margin-bottom: 32px;
            position: relative;
            overflow: hidden;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: linear-gradient(90deg, #ef5350, #ff9800, #ffc107, #66bb6a, #4fc3f7);
        }}
        .header h1 {{ font-size: 2.4rem; color: #58a6ff; margin-bottom: 8px; font-weight: 700; }}
        .header .subtitle {{ color: #8b949e; font-size: 1rem; }}

        /* Meta Grid */
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 32px;
        }}
        .meta-card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 16px;
        }}
        .meta-card .label {{ color: #8b949e; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; }}
        .meta-card .value {{ color: #c9d1d9; font-size: 1.05rem; font-weight: 600; margin-top: 4px; word-break: break-all; }}

        /* Score */
        .score-section {{ text-align: center; margin: 40px 0; }}
        .score-ring {{
            display: inline-flex; align-items: center; justify-content: center;
            width: 150px; height: 150px; border-radius: 50%;
            border: 8px solid {score_color};
            font-size: 3.2rem; font-weight: 800; color: {score_color};
            box-shadow: 0 0 30px {score_color}33;
            transition: transform 0.3s;
        }}
        .score-ring:hover {{ transform: scale(1.05); }}
        .score-label {{ margin-top: 12px; color: #8b949e; font-size: 0.9rem; }}

        /* Severity Grid */
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin: 32px 0;
        }}
        .severity-card {{
            text-align: center; padding: 24px 16px;
            background: #161b22; border: 1px solid #30363d; border-radius: 10px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .severity-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
        .severity-card .count {{ font-size: 2.8rem; font-weight: 800; }}
        .severity-card .sev-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 6px; }}
        .sev-critical {{ color: #ef5350; }}
        .sev-high {{ color: #ff9800; }}
        .sev-medium {{ color: #ffc107; }}
        .sev-low {{ color: #4fc3f7; }}

        /* Section */
        .section {{ margin: 40px 0; }}
        .section h2 {{
            font-size: 1.3rem; color: #58a6ff; margin-bottom: 20px;
            padding-bottom: 10px; border-bottom: 1px solid #30363d;
            display: flex; align-items: center; gap: 8px;
        }}

        /* Scanner Cards */
        .scanner-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }}
        .scanner-card {{
            background: #161b22; border: 1px solid #30363d; border-radius: 10px;
            padding: 20px; transition: border-color 0.2s;
        }}
        .scanner-card:hover {{ border-color: #58a6ff; }}
        .scanner-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }}
        .scanner-title {{ font-weight: 600; color: #c9d1d9; font-size: 0.95rem; }}
        .status-badge {{
            padding: 4px 10px; border-radius: 4px;
            font-size: 0.7rem; font-weight: 700; letter-spacing: 0.5px;
        }}
        .scanner-body {{ }}
        .metric-row {{
            display: flex; justify-content: space-between; padding: 7px 0;
            border-bottom: 1px solid #21262d; font-size: 0.9rem;
        }}
        .metric-row:last-child {{ border-bottom: none; }}
        .metric-label {{ color: #8b949e; }}
        .metric-value {{ color: #c9d1d9; font-weight: 600; }}

        /* Findings Table */
        .findings-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        .findings-table th {{
            background: #161b22; padding: 12px 14px; text-align: left;
            font-weight: 600; color: #58a6ff; border-bottom: 2px solid #30363d;
            position: sticky; top: 0;
        }}
        .findings-table td {{ padding: 10px 14px; border-bottom: 1px solid #21262d; }}
        .findings-table tr:hover {{ background: #161b22; }}
        .mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #79c0ff; }}
        .desc {{ color: #8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .target {{ color: #7ee787; font-size: 0.8rem; }}
        .sev-badge {{
            display: inline-block; padding: 3px 8px; border-radius: 4px;
            font-size: 0.7rem; font-weight: 700;
        }}
        .sev-badge.sev-critical {{ background: #b71c1c; color: #ef5350; }}
        .sev-badge.sev-high {{ background: #e65100; color: #ffa726; }}
        .sev-badge.sev-medium {{ background: #f57f17; color: #fff176; }}
        .sev-badge.sev-low {{ background: #0d47a1; color: #4fc3f7; }}

        /* Download Section */
        .download-grid {{ display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; }}
        .dl-btn {{
            display: inline-block; padding: 10px 20px;
            background: #21262d; color: #58a6ff; border: 1px solid #30363d;
            border-radius: 8px; text-decoration: none; font-size: 0.85rem;
            transition: background 0.2s, border-color 0.2s;
        }}
        .dl-btn:hover {{ background: #30363d; border-color: #58a6ff; }}

        /* Footer */
        .footer {{
            text-align: center; padding: 30px 0; margin-top: 50px;
            border-top: 1px solid #30363d; color: #8b949e; font-size: 0.8rem;
        }}

        /* Print */
        @media print {{
            body {{ background: #fff; color: #000; }}
            .scanner-card, .meta-card, .severity-card {{ border: 1px solid #ccc; background: #f9f9f9; }}
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .severity-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .scanner-grid {{ grid-template-columns: 1fr; }}
            .header h1 {{ font-size: 1.6rem; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Security Scan Report</h1>
        <p class="subtitle">{repo} &mdash; {scan_date}</p>
    </div>

    <div class="meta-grid">
        <div class="meta-card"><div class="label">Repository</div><div class="value">{repo}</div></div>
        <div class="meta-card"><div class="label">Branch</div><div class="value">{branch}</div></div>
        <div class="meta-card"><div class="label">Commit</div><div class="value">{commit}</div></div>
        <div class="meta-card"><div class="label">Languages</div><div class="value">{languages}</div></div>
        <div class="meta-card"><div class="label">Scan Date</div><div class="value">{scan_date}</div></div>
        <div class="meta-card"><div class="label">Scanners Run</div><div class="value">{scanners_run}</div></div>
    </div>

    <div class="score-section">
        <div class="score-ring">{score}</div>
        <p class="score-label">Security Score</p>
    </div>

    <div class="severity-grid">
        <div class="severity-card"><div class="count sev-critical">{critical}</div><div class="sev-label sev-critical">Critical</div></div>
        <div class="severity-card"><div class="count sev-high">{high}</div><div class="sev-label sev-high">High</div></div>
        <div class="severity-card"><div class="count sev-medium">{medium}</div><div class="sev-label sev-medium">Medium</div></div>
        <div class="severity-card"><div class="count sev-low">{low}</div><div class="sev-label sev-low">Low</div></div>
    </div>

    <div class="section">
        <h2>Scanner Results</h2>
        <div class="scanner-grid">{scanner_cards_html}</div>
    </div>

    <div class="section">
        <h2>Top Findings</h2>
        <div style="overflow-x:auto;border:1px solid #30363d;border-radius:10px;">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Scanner</th>
                        <th>ID</th>
                        <th>Description</th>
                        <th>Target</th>
                    </tr>
                </thead>
                <tbody>{findings_rows}</tbody>
            </table>
        </div>
    </div>

    <div class="section">
        <h2>Download Reports</h2>
        <div class="download-grid">
            <a class="dl-btn" href="summary.json">Summary JSON</a>
            <a class="dl-btn" href="trivy/trivy-report.json">Trivy JSON</a>
            <a class="dl-btn" href="gitleaks/gitleaks.json">Gitleaks JSON</a>
            <a class="dl-btn" href="semgrep/semgrep.json">Semgrep JSON</a>
            <a class="dl-btn" href="semgrep/semgrep.sarif">Semgrep SARIF</a>
            <a class="dl-btn" href="syft/sbom-cyclonedx.json">SBOM CycloneDX</a>
            <a class="dl-btn" href="syft/sbom-spdx.json">SBOM SPDX</a>
            <a class="dl-btn" href="grype/grype.json">Grype JSON</a>
            <a class="dl-btn" href="checkov/checkov.json">Checkov JSON</a>
            <a class="dl-btn" href="hadolint/hadolint.json">Hadolint JSON</a>
        </div>
    </div>

    <div class="footer">
        <p>Generated by Security Scanner &mdash; {scan_date}</p>
        <p style="margin-top:6px;font-size:0.75rem;color:#484f58;">Open this file directly in a browser for full styling</p>
    </div>
</div>

<script>
    // Add hover tooltips for findings
    document.querySelectorAll('.desc').forEach(el => {{
        el.title = el.textContent;
    }});
</script>
</body>
</html>'''


def generate_report(reports_dir, template_path, output_path):
    """Generate the HTML security report."""

    # Parse all scanner results
    profile = parse_profile(reports_dir)
    trivy = parse_trivy(reports_dir)
    gitleaks = parse_gitleaks(reports_dir)
    semgrep = parse_semgrep(reports_dir)
    grype = parse_grype(reports_dir)
    checkov = parse_checkov(reports_dir)
    hadolint = parse_hadolint(reports_dir)
    kube_linter = parse_kube_linter(reports_dir)
    syft = parse_syft(reports_dir)
    sonar = parse_sonar(reports_dir)

    # Calculate totals
    total_critical = trivy['critical'] + grype['critical']
    total_high = trivy['high'] + grype['high'] + semgrep['high'] + gitleaks['secrets_found']
    total_medium = trivy['medium'] + grype['medium'] + semgrep['medium']
    total_low = trivy['low'] + grype['low'] + semgrep['low']

    # Calculate security score
    score = calculate_score(trivy, gitleaks, semgrep, grype, checkov, hadolint, kube_linter)

    # Determine score color
    if score >= 80:
        score_class = 'score-good'
        score_border_color = '#66bb6a'
    elif score >= 60:
        score_class = 'score-medium'
        score_border_color = '#ffc107'
    elif score >= 40:
        score_class = 'score-high'
        score_border_color = '#ff9800'
    else:
        score_class = 'score-critical'
        score_border_color = '#ef5350'

    # Build scanner cards
    scanner_cards = ''

    # Trivy card
    trivy_total = trivy['critical'] + trivy['high'] + trivy['medium'] + trivy['low']
    trivy_status = 'fail' if trivy['critical'] > 0 else ('warn' if trivy['high'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'trivy', 'trivy-report.json')):
        trivy_status = 'skipped'
    scanner_cards += build_scanner_card('Trivy - Vulnerability Scan', trivy_status, [
        ('Critical', trivy['critical']),
        ('High', trivy['high']),
        ('Medium', trivy['medium']),
        ('Low', trivy['low']),
        ('Total', trivy_total),
    ])

    # Gitleaks card
    gl_status = 'fail' if gitleaks['secrets_found'] > 0 else 'pass'
    if not os.path.exists(os.path.join(reports_dir, 'gitleaks', 'gitleaks.json')):
        gl_status = 'skipped'
    scanner_cards += build_scanner_card('Gitleaks - Secret Detection', gl_status, [
        ('Secrets Found', gitleaks['secrets_found']),
    ])

    # Semgrep card
    semgrep_total = semgrep['high'] + semgrep['medium'] + semgrep['low']
    sg_status = 'fail' if semgrep['high'] > 0 else ('warn' if semgrep['medium'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'semgrep', 'semgrep.json')):
        sg_status = 'skipped'
    scanner_cards += build_scanner_card('Semgrep - Static Analysis', sg_status, [
        ('High', semgrep['high']),
        ('Medium', semgrep['medium']),
        ('Low', semgrep['low']),
        ('Total', semgrep_total),
    ])

    # SonarQube card
    sonar_status = 'pass'
    if sonar['vulnerabilities'] > 0 or sonar['bugs'] > 5:
        sonar_status = 'fail'
    elif sonar['code_smells'] > 10:
        sonar_status = 'warn'
    if not os.path.exists(os.path.join(reports_dir, 'sonar', 'sonar-measures.json')):
        sonar_status = 'skipped'
    scanner_cards += build_scanner_card('SonarQube - Code Quality', sonar_status, [
        ('Bugs', sonar['bugs']),
        ('Vulnerabilities', sonar['vulnerabilities']),
        ('Code Smells', sonar['code_smells']),
        ('Security Hotspots', sonar['hotspots']),
        ('Quality Gate', sonar['quality_gate']),
    ])

    # Syft card
    syft_status = 'pass' if syft['components'] > 0 else 'skipped'
    if not os.path.exists(os.path.join(reports_dir, 'syft', 'sbom-cyclonedx.json')):
        syft_status = 'skipped'
    scanner_cards += build_scanner_card('Syft - SBOM', syft_status, [
        ('Components', syft['components']),
    ])

    # Grype card
    grype_total = grype['critical'] + grype['high'] + grype['medium'] + grype['low']
    grype_status = 'fail' if grype['critical'] > 0 else ('warn' if grype['high'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'grype', 'grype.json')):
        grype_status = 'skipped'
    scanner_cards += build_scanner_card('Grype - Dependency Vulnerabilities', grype_status, [
        ('Critical', grype['critical']),
        ('High', grype['high']),
        ('Medium', grype['medium']),
        ('Low', grype['low']),
        ('Total', grype_total),
    ])

    # Checkov card
    ck_status = 'fail' if checkov['failed'] > 5 else ('warn' if checkov['failed'] > 0 else 'pass')
    if not os.path.exists(os.path.join(reports_dir, 'checkov', 'checkov.json')):
        ck_status = 'skipped'
    scanner_cards += build_scanner_card('Checkov - IaC Security', ck_status, [
        ('Passed', checkov['passed']),
        ('Failed', checkov['failed']),
        ('Skipped', checkov['skipped']),
    ])

    # Hadolint card
    hl_status = 'warn' if hadolint['issues'] > 0 else 'pass'
    if not os.path.exists(os.path.join(reports_dir, 'hadolint', 'hadolint.json')):
        hl_status = 'skipped'
    scanner_cards += build_scanner_card('Hadolint - Dockerfile Lint', hl_status, [
        ('Issues', hadolint['issues']),
    ])

    # kube-linter card
    kl_status = 'warn' if kube_linter['issues'] > 0 else 'pass'
    if not os.path.exists(os.path.join(reports_dir, 'kube-linter', 'kube-linter.json')):
        kl_status = 'skipped'
    scanner_cards += build_scanner_card('kube-linter - Kubernetes', kl_status, [
        ('Issues', kube_linter['issues']),
    ])

    # Collect all findings
    all_findings = (
        trivy['findings'] +
        gitleaks['findings'] +
        semgrep['findings'] +
        grype['findings'] +
        checkov['findings'] +
        hadolint['findings'] +
        kube_linter['findings']
    )

    findings_table = build_findings_table(all_findings)
    download_links = build_download_links(reports_dir)

    # Count scanners that actually ran
    scanners_run = sum(1 for s in [
        ('trivy', 'trivy/trivy-report.json'),
        ('gitleaks', 'gitleaks/gitleaks.json'),
        ('semgrep', 'semgrep/semgrep.json'),
        ('sonar', 'sonar/sonar-measures.json'),
        ('syft', 'syft/sbom-cyclonedx.json'),
        ('grype', 'grype/grype.json'),
        ('checkov', 'checkov/checkov.json'),
        ('hadolint', 'hadolint/hadolint.json'),
        ('kube-linter', 'kube-linter/kube-linter.json'),
    ] if os.path.exists(os.path.join(reports_dir, s[1])))

    # Load template
    try:
        with open(template_path, 'r') as f:
            template = f.read()
    except FileNotFoundError:
        print(f"[ERROR] Template not found: {template_path}")
        sys.exit(1)

    # Replace placeholders
    git_info = profile.get('git', {})
    replacements = {
        '{{ repository }}': profile.get('repository', 'Unknown'),
        '{{ branch }}': git_info.get('branch', 'unknown'),
        '{{ commit }}': git_info.get('commit', 'unknown'),
        '{{ languages }}': ', '.join(profile.get('languages', [])) or 'N/A',
        '{{ scan_date }}': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        '{{ scanners_run }}': str(scanners_run),
        '{{ security_score }}': str(score),
        '{{ score_class }}': score_class,
        '{{ score_border_color }}': score_border_color,
        '{{ critical_count }}': str(total_critical),
        '{{ high_count }}': str(total_high),
        '{{ medium_count }}': str(total_medium),
        '{{ low_count }}': str(total_low),
        '{{ scanner_cards }}': scanner_cards,
        '{{ findings_table }}': findings_table,
        '{{ download_links }}': download_links,
    }

    html = template
    for placeholder, value in replacements.items():
        html = html.replace(placeholder, str(value))

    # Write the inline-styled report (for Jenkins HTML Publisher)
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html)

    print(f"[OK] Report generated: {output_path}")

    # Generate the full standalone report with CSS + JS (for download)
    standalone_path = output_path.replace('.html', '-full.html')
    standalone_html = build_standalone_report(
        profile, score, score_border_color,
        total_critical, total_high, total_medium, total_low,
        trivy, gitleaks, semgrep, sonar, syft, grype, checkov, hadolint, kube_linter,
        all_findings, scanners_run, reports_dir
    )
    with open(standalone_path, 'w') as f:
        f.write(standalone_html)

    print(f"[OK] Standalone report: {standalone_path}")
    print(f"     Security Score: {score}/100")
    print(f"     Critical: {total_critical} | High: {total_high} | Medium: {total_medium} | Low: {total_low}")
    print(f"     Scanners Run: {scanners_run}")

    # Also write a JSON summary
    summary = {
        'repository': profile.get('repository', 'Unknown'),
        'scan_date': datetime.now().isoformat(),
        'security_score': score,
        'severity_counts': {
            'critical': total_critical,
            'high': total_high,
            'medium': total_medium,
            'low': total_low
        },
        'scanners_run': scanners_run,
        'trivy': {'critical': trivy['critical'], 'high': trivy['high'], 'medium': trivy['medium'], 'low': trivy['low']},
        'gitleaks': {'secrets_found': gitleaks['secrets_found']},
        'semgrep': {'high': semgrep['high'], 'medium': semgrep['medium'], 'low': semgrep['low']},
        'sonar': sonar,
        'grype': {'critical': grype['critical'], 'high': grype['high'], 'medium': grype['medium'], 'low': grype['low']},
        'checkov': {'passed': checkov['passed'], 'failed': checkov['failed']},
        'hadolint': {'issues': hadolint['issues']},
        'kube_linter': {'issues': kube_linter['issues']},
        'syft': {'components': syft['components']}
    }

    summary_path = os.path.join(reports_dir, 'summary.json')
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"     Summary JSON: {summary_path}")


def main():
    parser = argparse.ArgumentParser(description='Security Scanner Report Generator')
    parser.add_argument('--reports-dir', required=True, help='Path to reports directory')
    parser.add_argument('--template', required=True, help='Path to HTML template')
    parser.add_argument('--output', required=True, help='Output HTML report path')
    args = parser.parse_args()

    generate_report(args.reports_dir, args.template, args.output)


if __name__ == '__main__':
    main()
