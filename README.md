# OSBC OSS Audit Report Generator

A tool to generate a detailed HTML report from FOSSID OSS Audit Excel files.

**License:** Apache License 2.0
**Version:** 1.1  
**Release Date:** 2025-06-16

## Features
- Converts FOSSID OSS Audit Excel files (.xlsx) into interactive HTML reports
- Supports both online (CDN) and offline (no CDN) HTML templates
- Summarizes SBOM, license, and vulnerability data
- Batch processing for multiple Excel files
- Detailed logging with timestamps
- **Dependency Type column added to SBOM table (v1.1)**

## Change Log
- **v1.1 (2025-06-16)**
  - Added Dependency Type column to SBOM table (applied to both online/offline templates)
  - Added support for short command-line options: -o/-a/-d/-h (alongside --offline/--all/--debug/--help)
  - Improved help output for command-line usage
  - Miscellaneous bug fixes and code cleanup
- **v1.0 (2025-06-04)**
  - Initial public release as Windows EXE (no Python installation required)
  - All INFO logs now include timestamps and detailed progress for security sheet parsing
  - Batch mode (`--all`) shows progress (N of M files) and improved debug output

## How to Use (Windows, EXE version)

### 1. Download and Extract
- Download the provided `oss_audit_report.exe` file (or the distributed zip package).
- Extract all files to a folder (if provided as a zip).
- Make sure the Excel files you want to process are in the same folder as the EXE.

### 2. Basic Usage
Double-click `oss_audit_report.exe` or run from the command line:
```
oss_audit_report.exe <excel_filename>
```
- Generates an HTML report from the specified Excel file.

### 3. Options
- `--offline` : Use the offline HTML template (no CDN, works without internet)
- `--all`     : Process all `.xlsx` files in the current directory
- `--debug`   : Show detailed debug logs
- `--help`    : Show usage instructions
- `-o`        : Offline mode (shorthand)
- `-a`        : Process all files (shorthand)
- `-d`        : Debug mode (shorthand)
- `-h`        : Help (shorthand)

#### Examples
```
oss_audit_report.exe my_report.xlsx
oss_audit_report.exe my_report.xlsx --offline
oss_audit_report.exe my_report.xlsx --debug
oss_audit_report.exe --all
oss_audit_report.exe my_report.xlsx -o
oss_audit_report.exe my_report.xlsx -a
oss_audit_report.exe my_report.xlsx -d
oss_audit_report.exe -h
```

### 4. Output
- The generated HTML file will have the same name as the Excel file, with `.html` extension.
- Open the HTML file in your browser to view the report.

## Batch Processing
To process all Excel files in the current directory:
```
oss_audit_report.exe --all
```

## Logging
- All INFO logs include a timestamp.
- Progress and status messages are printed to the console.
- Use `--debug` for more detailed logs.

## COPYRIGHT
Copyright (c) 2025 jslee@osbc.co.kr