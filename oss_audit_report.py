import pandas as pd
import sys
import os
import json
import numpy as np
from collections import Counter
import requests
import logging
from datetime import datetime

SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low']

def find_column(row, candidates):
    for col in row.index:
        norm = col.replace(" ", "").lower()
        for cand in candidates:
            if norm == cand.replace(" ", "").lower():
                return col
    return None

def parse_dependency_type(row):
    """
    Dependencies path 컬럼을 파싱하여 Direct/Indirect 구분
    """
    dep_path = row.get("Dependencies path") or row.get("Dependencies Path")
    comp_name = str(row.get("Component Name") or "").strip()
    comp_ver = str(row.get("Component Version") or "").strip()
    if not dep_path or not isinstance(dep_path, str):
        return "Direct"
    # =>로 분리
    path_parts = [p.strip() for p in dep_path.split("=>")]
    if not path_parts:
        return "-"
    # 마지막 파트에서 이름/버전 추출
    last = path_parts[-1]
    # 이름:버전 패턴 찾기
    import re
    m = re.search(r'([\w\-@.]+):([\w\-.]+)$', last)
    if m:
        name, ver = m.group(1), m.group(2)
        # 이름/버전이 row와 일치하면 direct, 아니면 indirect
        if name in comp_name and (not comp_ver or ver in comp_ver):
            if len(path_parts) == 2:
                return "Direct"
            else:
                return "Indirect"
    # fallback: path 길이로 판단
    if len(path_parts) == 2:
        return "Direct"
    else:
        return "Indirect"

def process_sheet(df, src_type):
    def clean(val):
        if isinstance(val, float) and (pd.isnull(val) or np.isnan(val)):
            return ""
        if val is None:
            return ""
        return str(val).strip()
    result = []
    for _, row in df.iterrows():
        data = {
            "Source": src_type,
            "Component Name": clean(row.get("Component Name") or row.get("Dependency Name")),
            "Version": clean(row.get("Component Version") or row.get("Dependency Version")),
            "License Name": clean(row.get("Component license name") or row.get("Dependency license name")),
            "License Identifier": clean(row.get("Component license identifier") or row.get("Dependency license identifier")),
            "License Family": clean(row.get("Component license category") or row.get("Dependency license category")),
            "Severity": clean(row.get("Severity") or row.get("Risk") or row.get("risk")),
            "CVE": clean(row.get("CVE") or row.get("CVEs")),
            "Note": clean(row.get("Note") or row.get("Comment")),
            "URL": clean(row.get("URL") or row.get("url")),
            "PURL": clean(row.get("PURL") or row.get("purl")),
            "Download URL": clean(row.get("Download URL") or row.get("download url")),
        }
        # 항상 Dependency Type 필드를 추가 (Component는 '-')
        if src_type == "Dependency":
            data["Dependency Type"] = parse_dependency_type(row)
        else:
            data["Dependency Type"] = "-"
        result.append(data)
    return result

def parse_security(xl):
    df_vuln = pd.read_excel(xl, sheet_name='Vulnerabilities')
    df_comp = pd.read_excel(xl, sheet_name='Components')
    df_dep = pd.read_excel(xl, sheet_name='Dependency Analysis')
    cpe_to_comp = {str(row.get("CPE") or "").strip(): (str(row.get("Component Name") or "").strip(), str(row.get("Component Version") or "").strip()) for _, row in df_comp.iterrows()}
    cpe_to_dep = {str(row.get("CPE") or "").strip(): (str(row.get("Component Name") or "").strip(), str(row.get("Component Version") or "").strip()) for _, row in df_dep.iterrows()}
    security_rows = []
    total_rows = len(df_vuln)
    info_log(f"Security sheet parsing started: {total_rows} rows")
    for idx, (_, row) in enumerate(df_vuln.iterrows()):
        cpe = str(row.get("CPE") or "").strip()
        if cpe in cpe_to_comp:
            src = "Component"
            comp_name, comp_ver = cpe_to_comp[cpe]
        elif cpe in cpe_to_dep:
            src = "Dependency"
            comp_name, comp_ver = cpe_to_dep[cpe]
        else:
            src, comp_name, comp_ver = "Dependency", "-", "-"
        comp_name = comp_name or "-"
        comp_ver = comp_ver or "-"
        if total_rows > 0 and idx % max(1, total_rows // 12) == 0:
            percent = int((idx + 1) / total_rows * 100)
            info_log(f"Security parsing... {percent}% ({idx+1}/{total_rows})")
        sev_raw = str(row.get("Severity", "")).strip().split()
        severity = sev_raw[0].capitalize() if sev_raw else ""
        score = sev_raw[1] if len(sev_raw) > 1 else ""
        security_rows.append({
            "Source": src,
            "Component Name": comp_name,
            "Version": comp_ver,
            "CPE": cpe,
            "CVE": row.get("CVE", ""),
            "CVSS": row.get("CVSS", ""),
            "Severity": severity,
            "Score": score,
            "Attack Vector": row.get("Attack Vector", ""),
            "Attack Complexity": row.get("Attack Complexity", ""),
            "Availability Impact": row.get("Availability Impact", ""),
        })
    info_log("Security sheet parsing complete.")
    return security_rows

def annotate_sbom_with_severity(sbom_data, security_table):
    # index 취약점: (Comp Name, Version, Source, CVE) → Severity
    vuln_map = {}
    for sec in security_table:
        key = (sec.get('Component Name', ''), sec.get('Version', ''), sec.get('Source', ''), sec.get('CVE', ''))
        if sec.get('Severity'):
            vuln_map[key] = sec['Severity']
    for row in sbom_data:
        if row.get('CVE'):
            key = (row.get('Component Name', ''), row.get('Version', ''), row.get('Source', ''), row.get('CVE', ''))
            if key in vuln_map:
                row['Severity'] = vuln_map[key]
    return sbom_data

def get_fossid_version(xl):
    info_sheet = next((s for s in xl.sheet_names if 'scan information' in s.lower() or 'project scans' in s.lower()), None)
    if info_sheet:
        df_info = pd.read_excel(xl, sheet_name=info_sheet, header=None)
        for i, row in df_info.iterrows():
            for col in row:
                if isinstance(col, str) and "fossid version" in col.lower():
                    idx = row[row == col].index[0]
                    try:
                        right_val = row[idx+1]
                        if isinstance(right_val, str) and right_val.strip():
                            return right_val.strip()
                    except Exception:
                        pass
                    after = col.split(":", 1)[-1]
                    if "version" in after.lower() and after.strip():
                        ver = after.lower().split("version")[-1].strip()
                        if ver:
                            return ver
                    if ":" in col:
                        v = col.split(":")[-1].strip()
                        if v:
                            return v
    return "Unknown"

def get_project_name(xl):
    # 1순위: Project Information 시트에서 Project Name
    info_sheet = next((s for s in xl.sheet_names if 'project information' in s.lower()), None)
    if info_sheet:
        df_info = pd.read_excel(xl, sheet_name=info_sheet, header=None)
        for i, row in df_info.iterrows():
            for idx, col in enumerate(row):
                if isinstance(col, str) and "project name" in col.lower():
                    # 다음 셀에 값이 있는 경우
                    if idx+1 < len(row) and isinstance(row[idx+1], str):
                        return row[idx+1].strip()
                    # 'Project Name: XXX' 한 셀에 붙어있는 경우
                    if ':' in col:
                        return col.split(':',1)[-1].strip()
    # 2순위: Scan Information 시트에서 Scan Name
    scan_sheet = next((s for s in xl.sheet_names if 'scan information' in s.lower()), None)
    if scan_sheet:
        df_scan = pd.read_excel(xl, sheet_name=scan_sheet, header=None)
        for i, row in df_scan.iterrows():
            for idx, col in enumerate(row):
                if isinstance(col, str) and "scan name" in col.lower():
                    if idx+1 < len(row) and isinstance(row[idx+1], str):
                        return row[idx+1].strip()
                    if ':' in col:
                        return col.split(':',1)[-1].strip()
    return ""

def get_file_extensions(xl):
    iden_sheet = next((s for s in xl.sheet_names if 'identification' in s.lower()), None)
    if iden_sheet:
        df_iden = pd.read_excel(xl, sheet_name=iden_sheet)
        ext_counts = {}
        file_paths = df_iden.get('File path', []) if 'File path' in df_iden.columns else []
        for path in file_paths:
            if isinstance(path, str) and '.' in path:
                ext = path.strip().split('.')[-1].lower()
                if '/' in ext:
                    ext = ext.split('/')[0]
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
        return ext_counts
    return {}

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(
        description="OSBC OSS Audit Report Generator",
        add_help=False
    )
    parser.add_argument('excel_file', nargs='?', help='Input Excel filename')
    parser.add_argument('-o', '--offline', action='store_true', help='Use offline HTML template (no CDN)')
    parser.add_argument('-a', '--all', action='store_true', help='Process all Excel files in the current directory')
    parser.add_argument('-d', '--debug', action='store_true', help='Show detailed debug logs (step-by-step details)')
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    args = parser.parse_args()
    if args.help:
        print("""
OSBC OSS Audit Report Generator

Usage:
  oss_audit_report <excel_filename> [-o] [-a] [-d] [-h]

Options:
  -o, --offline   Use offline HTML template (no CDN)
  -a, --all       Process all Excel files in the current directory
  -d, --debug     Show detailed debug logs (step-by-step details)
  -h, --help      Show this help message and exit

Examples:
  oss_audit_report my_report.xlsx
  oss_audit_report my_report.xlsx -o
  oss_audit_report my_report.xlsx -d
  oss_audit_report -h
              
This script processes an Excel file generated by FOSSID OSS Audit and generates a detailed HTML report.
""")
        sys.exit(0)
    return args

def info_log(msg, debug=False, always_debug_msg=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if debug:
        print(f"[DEBUG] {timestamp} {msg}")
        if always_debug_msg:
            print(f"[DEBUG] {timestamp} {always_debug_msg}")
    else:
        print(f"[INFO] {timestamp} {msg}")

def log_progress(msg, percent):
    # Deprecated: do nothing (for backward compatibility)
    pass

def is_cdn_available(url="https://cdn.datatables.net/", debug=False):
    try:
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            info_log(f"CDN connection successful: {url}", debug)
            return True
        else:
            info_log(f"CDN connection failed (status {resp.status_code}): {url}", debug)
            return False
    except Exception as e:
        info_log(f"CDN connection exception: {e}", debug)
        return False

def resource_path(relative_path):
    # PyInstaller 환경에서는 _MEIPASS를 사용
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

def get_template_path(force_offline=False, debug=False):
    if force_offline:
        path = resource_path("oss_report_template-offline.html")
        info_log(f"[offline option] Using offline template: {path}", debug)
        return path
    if is_cdn_available(debug=debug):
        path = resource_path("oss_report_template-online.html")
        info_log(f"Using online template: {path}", debug)
        return path
    else:
        path = resource_path("oss_report_template-offline.html")
        info_log(f"Using offline template: {path}", debug)
        return path

def print_banner():
    print("""
=====================================
   OSBC OSS Audit Report Generator
=====================================
""")

def main():
    print_banner()
    args = parse_args()
    if args.all:
        excel_files = [f for f in os.listdir(os.getcwd()) if f.lower().endswith('.xlsx') and not f.startswith('~$') and not f.startswith('.')]
        total_files = len(excel_files)
        if not excel_files:
            print("No Excel files found in the current directory.")
            sys.exit(1)
        for i, excel_file in enumerate(excel_files, 1):
            info_log(f"[--all] Processing file {i}/{total_files}: {excel_file}", args.debug)
            if args.debug:
                info_log(f"[--all] File list: {excel_files}", True)
                info_log(f"[--all] Now processing: {excel_file} (index {i-1})", True)
            try:
                process_excel(excel_file, args)
            except Exception as e:
                print(f"[ERROR] Failed to process {excel_file}: {e}")
        info_log(f"[--all] All {total_files} Excel files processed.", args.debug)
        return
    if not args.excel_file:
        print("Usage: python oss_audit_report <excel_filename> [--offline] [--debug] [--all]")
        sys.exit(1)
    process_excel(args.excel_file, args)

def process_excel(excel_file, args):
    force_offline = args.offline
    debug = args.debug
    html_file = os.path.splitext(excel_file)[0] + ".html"
    info_log(f"Loading Excel file: {excel_file}", debug)
    if debug:
        info_log(f"Current working directory: {os.getcwd()}", True)
        info_log(f"Python version: {sys.version}", True)
        info_log(f"Pandas version: {pd.__version__}", True)
    xl = pd.ExcelFile(excel_file)
    comp_sheet = next((s for s in xl.sheet_names if 'component' in s.lower()), xl.sheet_names[0])
    dep_sheet = next((s for s in xl.sheet_names if 'depend' in s.lower()), xl.sheet_names[1])
    info_log(f"Reading component/dependency sheets: {comp_sheet}, {dep_sheet}", debug)
    df_comp = pd.read_excel(xl, sheet_name=comp_sheet)
    df_dep = pd.read_excel(xl, sheet_name=dep_sheet)
    if debug:
        info_log(f"Component sheet rows: {len(df_comp)}", True)
        info_log(f"Dependency sheet rows: {len(df_dep)}", True)
        info_log(f"Component columns: {list(df_comp.columns)}", True)
        info_log(f"Dependency columns: {list(df_dep.columns)}", True)
    info_log("Processing SBOM data...", debug)
    sbom_data = process_sheet(df_comp, "Component") + process_sheet(df_dep, "Dependency")
    if debug:
        info_log(f"SBOM data count: {len(sbom_data)}", True)
    info_log("Parsing security data...", debug)
    security_table = parse_security(xl)
    if debug:
        info_log(f"Security table count: {len(security_table)}", True)
    info_log("Annotating SBOM with severity...", debug)
    sbom_data = annotate_sbom_with_severity(sbom_data, security_table)
    info_log("Building legal table...", debug)
    legal_table = {}
    for row in sbom_data:
        k = (
            row["License Family"] or "Unknown",
            row["License Name"] or "Unknown",
            row["License Identifier"] or "",
        )
        if k not in legal_table:
            legal_table[k] = {
                "License Family": k[0],
                "License Name": k[1],
                "License Identifier": k[2],
                "Component Count": 0
            }
        legal_table[k]["Component Count"] += 1
    legal_table_list = list(legal_table.values())
    if debug:
        info_log(f"Legal table unique keys: {len(legal_table_list)}", True)
    info_log("Summarizing data...", debug)
    summary_data = {
        "total": len(sbom_data),
        "components": sum(1 for row in sbom_data if row["Source"] == "Component"),
        "dependencies": sum(1 for row in sbom_data if row["Source"] == "Dependency"),
        "uniqueLicenses": len(set(row["License Identifier"] for row in sbom_data if row.get("License Identifier"))),
        "critical": sum(1 for row in security_table if row["Severity"] == "Critical"),
        "high": sum(1 for row in security_table if row["Severity"] == "High"),
        "medium": sum(1 for row in security_table if row["Severity"] == "Medium"),
        "low": sum(1 for row in security_table if row["Severity"] == "Low"),
    }
    if debug:
        info_log(f"Summary: {summary_data}", True)
    risk_stats = Counter((row.get("Severity") or "").capitalize() for row in security_table if (row.get("Severity") or "").capitalize() in SEVERITY_ORDER)
    for sev in SEVERITY_ORDER:
        risk_stats.setdefault(sev, 0)
    license_family_stats = Counter([row["License Family"] or "Unknown" for row in sbom_data])
    ext_stats = get_file_extensions(xl)
    if debug:
        info_log(f"File extension stats: {ext_stats}", True)
    data_js = {
        "summary": summary_data,
        "sbom": sbom_data,
        "licenseStats": dict(license_family_stats),
        "riskStats": dict(risk_stats),
        "legalTable": legal_table_list,
        "securityTable": security_table,
        "extStats": ext_stats,
    }
    fossid_version = get_fossid_version(xl)
    project_name = get_project_name(xl)
    if debug:
        info_log(f"FOSSID version: {fossid_version}", True)
        info_log(f"Project name: {project_name}", True)
    info_log("Finalizing and writing HTML...", debug)
    html_template_path = get_template_path(force_offline=force_offline, debug=debug)
    if debug:
        info_log(f"HTML template path: {html_template_path}", True)
    try:
        with open(html_template_path, encoding='utf-8') as f:
            html = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read template: {e}")
        return
    try:
        html = html.replace('/*__OSS_DATA__*/', 'window.ossData = ' + json.dumps(data_js, ensure_ascii=False, indent=2) + ';')
        html = html.replace('{{FOSSID_VERSION}}', fossid_version)
        html = html.replace('{{PROJECT_NAME}}', project_name)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html)
    except Exception as e:
        print(f"[ERROR] Failed to write HTML file: {e}")
        return
    info_log("Done! Report generated.", debug)
    info_log(f"{html_file} generated! Open in your browser.", debug)

if __name__ == "__main__":
    main()
