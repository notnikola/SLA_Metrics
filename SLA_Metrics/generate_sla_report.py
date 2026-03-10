#!/usr/bin/env python3
"""
SLA Metrics Dashboard Generator

Generates an HTML dashboard showing vulnerability management SLA compliance
by Division and Team (e.g., OIT Desktop, CID Desktop, RL Infrastructure, etc.)

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

try:
    import openpyxl
except ImportError:
    print("Error: openpyxl is required. Install with: pip install openpyxl")
    exit(1)

# Configuration
BASE_DIR = Path(__file__).parent
REPORT_DATE = datetime.now()
AGE_BUCKETS = [8, 16, 31, 91]  # Days

# Division + Team combinations to report on
# Format: (display_name, division, team_keyword_in_boundaries)
DIVISION_TEAMS = [
    ("OIT Desktop", "OIT", "Desktop Team"),
    ("CID Desktop", "CID", "Desktop Team"),
    ("RL Desktop", "RL", "Desktop Team"),
    ("OIT Infrastructure", "OIT", "Infrastructure Team"),
    ("RL Infrastructure", "RL", "Infrastructure Team"),
    ("OIT Network", "OIT", "Network Team"),
    ("OIT Mobile", "OIT", "Mobile Devices Team"),
]

# Default data file - supports both xlsx and csv
DATA_FILE_XLSX = BASE_DIR / "report_Enriched.xlsx"
DATA_FILE_CSV = BASE_DIR / "report_Enriched.csv"
DATA_SHEET = "report_Enriched"

# CSV column names (matching xlsx headers)
CSV_COLUMNS = {
    'cve_uid': 'Vulnerability CVE UID',
    'avm_rating': 'AVM Rating',
    'status': 'Status',
    'first_detected': 'First Detected',
    'boundaries': 'Boundaries',
    'division': 'Division',
}

# SLA targets in business days
SLA_TARGETS = {
    "CRITICAL": 7,
    "HIGH": 14
}

# Column indices in xlsx file (0-based)
COLUMN_INDICES = {
    'cve_uid': 0,           # Vulnerability CVE UID
    'avm_rating': 4,        # AVM Rating
    'status': 6,            # Status
    'first_detected': 9,    # First Detected
    'boundaries': 30,       # Boundaries
    'division': 43,         # Division
}


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


def load_xlsx_data(file_path: Path, sheet_name: str) -> list[tuple]:
    """Load data from xlsx file and return rows as tuples."""
    wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
    ws = wb[sheet_name]

    rows = []
    for i, row in enumerate(ws.iter_rows(min_row=2, values_only=True)):
        rows.append(row)

    wb.close()
    return rows


def load_csv_data(file_path: Path) -> list[tuple]:
    """Load data from CSV file and return rows as tuples matching xlsx column order."""
    rows = []

    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Build tuple in same order as xlsx columns (44 columns)
            # Only the columns we need are at specific indices
            row_data = [None] * 44
            row_data[COLUMN_INDICES['cve_uid']] = row.get(CSV_COLUMNS['cve_uid'], '')
            row_data[COLUMN_INDICES['avm_rating']] = row.get(CSV_COLUMNS['avm_rating'], '')
            row_data[COLUMN_INDICES['status']] = row.get(CSV_COLUMNS['status'], '')
            row_data[COLUMN_INDICES['first_detected']] = row.get(CSV_COLUMNS['first_detected'], '')
            row_data[COLUMN_INDICES['boundaries']] = row.get(CSV_COLUMNS['boundaries'], '')
            row_data[COLUMN_INDICES['division']] = row.get(CSV_COLUMNS['division'], '')
            rows.append(tuple(row_data))

    return rows


def load_data() -> tuple[list[tuple], str]:
    """Load data from xlsx or csv file. Returns (rows, filename)."""
    if DATA_FILE_XLSX.exists():
        return load_xlsx_data(DATA_FILE_XLSX, DATA_SHEET), DATA_FILE_XLSX.name
    elif DATA_FILE_CSV.exists():
        return load_csv_data(DATA_FILE_CSV), DATA_FILE_CSV.name
    else:
        return None, None


def parse_vulnerabilities_for_division_team(
    rows: list[tuple],
    division: str,
    team_keyword: str
) -> list[dict]:
    """Parse vulnerabilities from xlsx data for a specific division+team.

    Filters by division and team (from Boundaries field).
    Deduplicates by CVE UID, using the earliest first detected date
    and considering a CVE as 'Open' if ANY instance is open.
    """
    # Track unique CVEs: {cve_uid: {data}}
    cve_tracker = {}

    for row in rows:
        try:
            # Get values from row
            cve_uid = str(row[COLUMN_INDICES['cve_uid']] or '').strip()
            avm_rating = str(row[COLUMN_INDICES['avm_rating']] or '').strip().upper()
            status = str(row[COLUMN_INDICES['status']] or '').strip()
            first_detected_val = row[COLUMN_INDICES['first_detected']]
            boundaries = str(row[COLUMN_INDICES['boundaries']] or '').strip()
            row_division = str(row[COLUMN_INDICES['division']] or '').strip()

            # Filter by division and team
            if row_division != division:
                continue
            if team_keyword.lower() not in boundaries.lower():
                continue

            # Skip if missing critical data
            if not cve_uid or not avm_rating:
                continue

            # Only include CRITICAL and HIGH
            if avm_rating not in ['CRITICAL', 'HIGH']:
                continue

            # Parse date - handle both string and datetime objects
            if isinstance(first_detected_val, datetime):
                first_detected = first_detected_val
            else:
                first_detected_str = str(first_detected_val or '').strip()
                if not first_detected_str:
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

    # Add division+team tables
    for display_name, _, _ in DIVISION_TEAMS:
        if display_name in all_team_data:
            html += generate_team_table(display_name, all_team_data[display_name])

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

    # Load data from xlsx or csv
    rows, filename = load_data()
    if rows is None:
        print(f"[ERROR] Data file not found. Expected one of:")
        print(f"  - {DATA_FILE_XLSX}")
        print(f"  - {DATA_FILE_CSV}")
        return

    print(f"Loading data from: {filename}")
    print(f"Total rows loaded: {len(rows)}\n")

    all_team_data = {}

    for display_name, division, team_keyword in DIVISION_TEAMS:
        print(f"Processing {display_name}...")

        vulnerabilities = parse_vulnerabilities_for_division_team(rows, division, team_keyword)
        print(f"  Unique CVEs: {len(vulnerabilities)}")

        if vulnerabilities:
            aggregated = aggregate_data(vulnerabilities)
            all_team_data[display_name] = aggregated

            # Print summary for this division+team
            open_critical = sum(aggregated['Open']['CRITICAL'].values())
            open_high = sum(aggregated['Open']['HIGH'].values())
            print(f"  Open Critical: {open_critical}")
            print(f"  Open High: {open_high}")
        else:
            print("  No vulnerabilities found")
        print()

    if not all_team_data:
        print("[ERROR] No data found. Exiting.")
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
