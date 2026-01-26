#!/usr/bin/env python3
"""
SLA Metrics Dashboard Generator

Generates an HTML dashboard showing vulnerability management SLA compliance
for Desktop, Infrastructure, and Network teams.

SLA Targets:
- Critical: 7 business days
- High: 14 business days

Age Buckets: 8, 16, 31, 91 days from first detection
Color Coding: Green (compliant), Yellow (warning), Red (overdue), Black (severely overdue)
"""

import csv
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# Configuration
BASE_DIR = Path(__file__).parent
REPORT_DATE = datetime.now()
AGE_BUCKETS = [8, 16, 31, 91]  # Days

# Team directory mappings
TEAMS = {
    "Desktop": "Desktop_Vulnerabilities",
    "Infrastructure": "Infrastructure_Vulnerabilities",
    "Network": "Network_Vulnerabilities"
}

# SLA targets in business days
SLA_TARGETS = {
    "CRITICAL": 7,
    "HIGH": 14
}


def find_related_devices_file(team_dir: Path) -> Path | None:
    """Find the Related Devices CSV file in a team directory."""
    for file in team_dir.glob("Related Devices*.csv"):
        return file
    return None


def parse_date(date_str: str) -> datetime | None:
    """Parse date string from CSV."""
    if not date_str or date_str.strip() == "":
        return None
    try:
        # Format: 2025-12-12 01:53:38
        return datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def calculate_age_days(first_detected: datetime, reference_date: datetime = None) -> int:
    """Calculate age in calendar days from first detection.""" 
    if reference_date is None:
        reference_date = REPORT_DATE
    delta = reference_date - first_detected
    return delta.days


def get_age_bucket(age_days: int) -> str:
    """Determine which age bucket a vulnerability falls into."""
    if age_days <= 8:
        return "≤8"
    elif age_days <= 16:
        return "9-16"
    elif age_days <= 31:
        return "17-31"
    elif age_days <= 91:
        return "32-91"
    else:
        return ">91"


def get_bucket_color(bucket: str, criticality: str) -> str:
    """
    Determine color based on bucket and criticality.

    For Critical (7 day SLA):
    - ≤8 days: Green (just past SLA, acceptable)
    - 9-16 days: Yellow (warning)
    - 17-31 days: Red (overdue)
    - 32-91+ days: Black (severely overdue)

    For High (14 day SLA):
    - ≤8 days: Green (within SLA)
    - 9-16 days: Green/Yellow (at/just past SLA)
    - 17-31 days: Yellow/Red (overdue)
    - 32-91+ days: Red/Black (severely overdue)
    """
    if criticality == "CRITICAL":
        colors = {
            "≤8": "#28a745",      # Green
            "9-16": "#ffc107",    # Yellow
            "17-31": "#dc3545",   # Red
            "32-91": "#212529",   # Black
            ">91": "#212529"      # Black
        }
    else:  # HIGH
        colors = {
            "≤8": "#28a745",      # Green
            "9-16": "#7cb342",    # Light Green (at SLA boundary)
            "17-31": "#ffc107",   # Yellow
            "32-91": "#dc3545",   # Red
            ">91": "#212529"      # Black
        }
    return colors.get(bucket, "#6c757d")


def parse_vulnerabilities(file_path: Path) -> list[dict]:
    """Parse vulnerabilities from a Related Devices CSV file.

    Deduplicates by CVE UID, using the earliest first detected date
    and considering a CVE as 'Open' if ANY instance is open.
    """
    # Track unique CVEs: {cve_uid: {data}}
    cve_tracker = {}

    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                cve_uid = row.get('Vulnerability CVE UID', '').strip()
                avm_rating = row.get('AVM Rating', '').strip().upper()
                status = row.get('Status', '').strip()
                first_detected_str = row.get('First Detected', '').strip()

                # Skip if missing critical data
                if not cve_uid or not avm_rating or not first_detected_str:
                    continue

                # Only include CRITICAL and HIGH
                if avm_rating not in ['CRITICAL', 'HIGH']:
                    continue

                first_detected = parse_date(first_detected_str)
                if not first_detected:
                    continue

                # Normalize status
                if 'open' in status.lower():
                    normalized_status = 'Open'
                elif 'remediat' in status.lower() or 'resolve' in status.lower() or 'closed' in status.lower():
                    normalized_status = 'Remediated'
                else:
                    normalized_status = 'Open'  # Default to open if unclear

                # Track unique CVEs
                if cve_uid not in cve_tracker:
                    cve_tracker[cve_uid] = {
                        'cve_uid': cve_uid,
                        'avm_rating': avm_rating,
                        'status': normalized_status,
                        'first_detected': first_detected,
                        'instance_count': 1
                    }
                else:
                    # Use earliest first detected date
                    if first_detected < cve_tracker[cve_uid]['first_detected']:
                        cve_tracker[cve_uid]['first_detected'] = first_detected
                    # If ANY instance is Open, mark CVE as Open
                    if normalized_status == 'Open':
                        cve_tracker[cve_uid]['status'] = 'Open'
                    cve_tracker[cve_uid]['instance_count'] += 1

            except Exception as e:
                continue  # Skip malformed rows

    # Convert to list and calculate age buckets
    vulnerabilities = []
    for cve_data in cve_tracker.values():
        cve_data['age_days'] = calculate_age_days(cve_data['first_detected'])
        cve_data['age_bucket'] = get_age_bucket(cve_data['age_days'])
        vulnerabilities.append(cve_data)

    return vulnerabilities


def aggregate_data(vulnerabilities: list[dict]) -> dict:
    """Aggregate vulnerabilities by status, criticality, and age bucket."""
    # Structure: {status: {criticality: {bucket: count}}}
    buckets = ["≤8", "9-16", "17-31", "32-91", ">91"]

    aggregated = {
        'Open': {
            'CRITICAL': {b: 0 for b in buckets},
            'HIGH': {b: 0 for b in buckets}
        },
        'Remediated': {
            'CRITICAL': {b: 0 for b in buckets},
            'HIGH': {b: 0 for b in buckets}
        }
    }

    for vuln in vulnerabilities:
        status = vuln['status']
        criticality = vuln['avm_rating']
        bucket = vuln['age_bucket']

        if status in aggregated and criticality in aggregated[status]:
            aggregated[status][criticality][bucket] += 1

    return aggregated


def generate_team_table(team_name: str, data: dict) -> str:
    """Generate HTML table for a single team."""
    buckets = ["≤8", "9-16", "17-31", "32-91", ">91"]
    bucket_headers = ["≤8 days", "9-16 days", "17-31 days", "32-91 days", ">91 days"]

    html = f'''
    <div class="team-card">
        <h2>{team_name} Team</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Criticality</th>
                    <th>SLA</th>
'''

    for header in bucket_headers:
        html += f'                    <th>{header}</th>\n'

    html += '''                    <th>Total</th>
                </tr>
            </thead>
            <tbody>
'''

    for status in ['Open', 'Remediated']:
        for criticality in ['CRITICAL', 'HIGH']:
            sla = f"{SLA_TARGETS[criticality]} days"
            row_data = data[status][criticality]
            total = sum(row_data.values())

            html += f'''                <tr>
                    <td class="status-{status.lower()}">{status}</td>
                    <td class="criticality-{criticality.lower()}">{criticality}</td>
                    <td>{sla}</td>
'''

            for bucket in buckets:
                count = row_data[bucket]
                color = get_bucket_color(bucket, criticality)
                text_color = "#ffffff" if color in ["#212529", "#dc3545"] else "#000000"

                # Only color cells with values > 0
                if count > 0:
                    html += f'                    <td style="background-color: {color}; color: {text_color}; font-weight: bold;">{count}</td>\n'
                else:
                    html += f'                    <td class="zero-cell">0</td>\n'

            html += f'                    <td class="total-cell">{total}</td>\n'
            html += '                </tr>\n'

    html += '''            </tbody>
        </table>
    </div>
'''
    return html


def generate_summary_table(all_team_data: dict) -> str:
    """Generate an executive summary table across all teams."""
    buckets = ["≤8", "9-16", "17-31", "32-91", ">91"]

    # Aggregate across all teams
    summary = {
        'Open': {'CRITICAL': {b: 0 for b in buckets}, 'HIGH': {b: 0 for b in buckets}},
        'Remediated': {'CRITICAL': {b: 0 for b in buckets}, 'HIGH': {b: 0 for b in buckets}}
    }

    for team_data in all_team_data.values():
        for status in ['Open', 'Remediated']:
            for criticality in ['CRITICAL', 'HIGH']:
                for bucket in buckets:
                    summary[status][criticality][bucket] += team_data[status][criticality][bucket]

    # Calculate key metrics
    total_open_critical = sum(summary['Open']['CRITICAL'].values())
    total_open_high = sum(summary['Open']['HIGH'].values())

    # Out of SLA calculations
    critical_out_of_sla = sum(summary['Open']['CRITICAL'][b] for b in ["9-16", "17-31", "32-91", ">91"])
    high_out_of_sla = sum(summary['Open']['HIGH'][b] for b in ["17-31", "32-91", ">91"])

    critical_compliance = ((total_open_critical - critical_out_of_sla) / total_open_critical * 100) if total_open_critical > 0 else 100
    high_compliance = ((total_open_high - high_out_of_sla) / total_open_high * 100) if total_open_high > 0 else 100

    html = '''
    <div class="summary-section">
        <h2>Executive Summary</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Open Critical Vulnerabilities</div>
                <div class="metric-value critical">{}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Open High Vulnerabilities</div>
                <div class="metric-value high">{}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Critical SLA Compliance</div>
                <div class="metric-value {}">{:.1f}%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">High SLA Compliance</div>
                <div class="metric-value {}">{:.1f}%</div>
            </div>
        </div>

        <div class="sla-info">
            <h3>SLA Targets</h3>
            <ul>
                <li><strong>Critical:</strong> 7 business days from first
                detection</li>
                <li><strong>High:</strong> 14 business days from first
                detection</li>
            </ul>
        </div>

        <div class="legend">
            <h3>Color Legend</h3>
            <div class="legend-items">
                <span class="legend-item" style="background-color: #28a745;">Within/Near SLA</span>
                <span class="legend-item" style="background-color: #ffc107; color: #000;">Warning</span>
                <span class="legend-item" style="background-color: #dc3545;">Overdue</span>
                <span class="legend-item" style="background-color: #212529;">Severely Overdue</span>
            </div>
        </div>
    </div>
'''.format(
        total_open_critical,
        total_open_high,
        "good" if critical_compliance >= 80 else "warning" if critical_compliance >= 60 else "bad",
        critical_compliance,
        "good" if high_compliance >= 80 else "warning" if high_compliance >= 60 else "bad",
        high_compliance
    )

    return html


def generate_html_report(all_team_data: dict) -> str:
    """Generate complete HTML report."""
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Management SLA Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            color: white;
            padding: 30px 40px;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        header h1 {{
            font-size: 28px;
            margin-bottom: 8px;
        }}

        header .subtitle {{
            font-size: 14px;
            opacity: 0.9;
        }}

        .summary-section {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }}

        .summary-section h2 {{
            color: #1a237e;
            margin-bottom: 20px;
            font-size: 22px;
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }}

        .metric-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #1a237e;
        }}

        .metric-label {{
            font-size: 13px;
            color: #666;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .metric-value {{
            font-size: 32px;
            font-weight: bold;
        }}

        .metric-value.critical {{
            color: #dc3545;
        }}

        .metric-value.high {{
            color: #fd7e14;
        }}

        .metric-value.good {{
            color: #28a745;
        }}

        .metric-value.warning {{
            color: #ffc107;
        }}

        .metric-value.bad {{
            color: #dc3545;
        }}

        .sla-info, .legend {{
            margin-top: 20px;
        }}

        .sla-info h3, .legend h3 {{
            font-size: 16px;
            color: #444;
            margin-bottom: 10px;
        }}

        .sla-info ul {{
            list-style: none;
            padding-left: 0;
        }}

        .sla-info li {{
            padding: 5px 0;
            color: #555;
        }}

        .legend-items {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}

        .legend-item {{
            padding: 8px 16px;
            border-radius: 4px;
            color: white;
            font-size: 13px;
            font-weight: 500;
        }}

        .team-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }}

        .team-card h2 {{
            color: #1a237e;
            margin-bottom: 20px;
            font-size: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}

        th {{
            background-color: #37474f;
            color: white;
            padding: 12px 10px;
            text-align: center;
            font-weight: 600;
            font-size: 13px;
        }}

        th:first-child, th:nth-child(2), th:nth-child(3) {{
            text-align: left;
        }}

        td {{
            padding: 12px 10px;
            text-align: center;
            border-bottom: 1px solid #e0e0e0;
        }}

        td:first-child, td:nth-child(2), td:nth-child(3) {{
            text-align: left;
        }}

        .status-open {{
            color: #dc3545;
            font-weight: 600;
        }}

        .status-remediated {{
            color: #28a745;
            font-weight: 600;
        }}

        .criticality-critical {{
            background-color: #ffebee;
            color: #c62828;
            font-weight: 600;
            border-radius: 3px;
            padding: 4px 8px;
        }}

        .criticality-high {{
            background-color: #fff3e0;
            color: #e65100;
            font-weight: 600;
            border-radius: 3px;
            padding: 4px 8px;
        }}

        .zero-cell {{
            color: #aaa;
        }}

        .total-cell {{
            font-weight: bold;
            background-color: #f5f5f5;
        }}

        tr:hover {{
            background-color: #fafafa;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
        }}

        @media print {{
            body {{
                background-color: white;
            }}

            .container {{
                max-width: 100%;
            }}

            .team-card, .summary-section {{
                box-shadow: none;
                border: 1px solid #ddd;
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Vulnerability Management SLA Dashboard</h1>
            <div class="subtitle">Generated: {REPORT_DATE.strftime("%B %d, %Y at %I:%M %p")}</div>
        </header>
'''

    # Add executive summary
    html += generate_summary_table(all_team_data)

    # Add team tables
    for team_name in ["Desktop", "Infrastructure", "Network"]:
        if team_name in all_team_data:
            html += generate_team_table(team_name, all_team_data[team_name])

    html += '''
        <footer>
            <p>Vulnerability Management Program - SLA Compliance Report</p>
            <p>Age buckets represent calendar days from first detection</p>
        </footer>
    </div>
</body>
</html>
'''
    return html


def main():
    """Main entry point."""
    print("=" * 60)
    print("Vulnerability Management SLA Report Generator")
    print("=" * 60)
    print(f"\nReport Date: {REPORT_DATE.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Base Directory: {BASE_DIR}\n")

    all_team_data = {}

    for team_name, team_dir_name in TEAMS.items():
        team_dir = BASE_DIR / team_dir_name

        if not team_dir.exists():
            print(f"[WARNING] Directory not found: {team_dir}")
            continue

        related_devices_file = find_related_devices_file(team_dir)

        if not related_devices_file:
            print(f"[WARNING] No Related Devices file found for {team_name}")
            continue

        print(f"Processing {team_name}...")
        print(f"  File: {related_devices_file.name}")

        vulnerabilities = parse_vulnerabilities(related_devices_file)
        print(f"  Unique CVEs: {len(vulnerabilities)}")

        aggregated = aggregate_data(vulnerabilities)
        all_team_data[team_name] = aggregated

        # Print summary for this team
        open_critical = sum(aggregated['Open']['CRITICAL'].values())
        open_high = sum(aggregated['Open']['HIGH'].values())
        print(f"  Open Critical: {open_critical}")
        print(f"  Open High: {open_high}")
        print()

    if not all_team_data:
        print("[ERROR] No team data found. Exiting.")
        return

    # Generate HTML report
    html_content = generate_html_report(all_team_data)

    output_file = BASE_DIR / "sla_dashboard.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print("=" * 60)
    print(f"Report generated successfully!")
    print(f"Output: {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()
