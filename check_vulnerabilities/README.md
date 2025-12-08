# Shai-Hulud NPM Supply Chain Malware Scanner

A comprehensive, asynchronous scanner for detecting indicators of compromise (IoCs) related to the Shai-Hulud npm supply chain attack and related threats (CrowdStrike, Unit42, etc.) in GitHub organizations. The tool generates a CSV report and detailed logs for security review and incident response.

---

## Table of Contents

- [Features](#features)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Detection Logic](#detection-logic)
- [Class & Function Overview](#class--function-overview)
- [Output](#output)
- [Mitigation & Response](#mitigation--response)
- [References](#references)

---

## Features

- **Malicious Repository Detection:** Finds repositories named "Shai-Hulud" or with suspicious migration descriptions.
- **Malicious Branch Detection:** Identifies branches named "shai-hulud" across all repos.
- **Malicious Workflow Detection:** Detects suspicious GitHub Actions workflows (e.g., `shai-hulud-workflow.yml`).
- **Compromised Package Detection:** Scans for known compromised npm packages (CrowdStrike, Unit42, etc.).
- **Malicious File Hash Detection:** Checks for known malicious `bundle.js` hashes and suspicious code patterns.
- **AI-Generated Malware Patterns:** Flags files with high density of AI-generated code patterns and malicious content.
- **CSV Reporting:** Exports all findings to a CSV file for audit and incident response.
- **Detailed Logging:** Logs errors and debug information to `logs/error/` and `logs/debug/`.

---

## Setup & Installation

1. **Clone the repository** and navigate to the scanner directory:
    ```bash
    cd check_vulnerabilities
    ```

2. **Install Python dependencies:**
    ```bash
    pip3 install -r requirements.txt
    ```

3. **Set your GitHub Personal Access Token (PAT):**
    ```bash
    export GH_PAT=<your_github_pat>
    ```

    - The PAT must have at least [repo](http://_vscodecontentref_/1), [read:org](http://_vscodecontentref_/2), and [read:packages](http://_vscodecontentref_/3) permissions.

4. **Make the scan script executable:**
    ```bash
    chmod +x ./scan.sh
    ```

---

## Usage

1. **Edit [scan.sh](http://_vscodecontentref_/4)** to set your organization name:
    ```sh
    ORG_NAME=your-org-name
    python3 scanner_script.py "$GH_PAT" "$ORG_NAME"
    ```

2. **Run the scan:**
    ```bash
    ./scan.sh
    ```

3. **Review the output:**
    - CSV results: `<org_name>_shai_hulud_detection_results_<timestamp>.csv`
    - Debug logs: `logs/debug/`
    - Error logs: `logs/error/`

---

## Detection Logic

Based on the CrowdStrike/Unit42 PDF:

- **Malicious Repository Names:**  
  - `Shai-Hulud`
  - Migration repositories with "Shai-Hulud Migration" in the description

- **Malicious Branches:**  
  - Any branch named `shai-hulud`

- **Malicious Workflows:**  
  - Workflow files: `.github/workflows/shai-hulud-workflow.yml`, `.github/workflows/shai-hulud.yaml`
  - Workflow names containing `shai-hulud` or `migration`

- **Compromised Packages:**  
  - Packages listed in the PDF and threat intelligence (CrowdStrike, Unit42, etc.)

- **Malicious Files:**  
  - `bundle.js` files with known malicious SHA256 hashes
  - Files containing suspicious patterns: `webhook.site`, `5.199.166.1`, `TruffleHog`, `postinstall` scripts, etc.

- **AI-Generated Malware:**  
  - Files with high density of AI-generated code comments and malicious content

---

## Class & Function Overview

### [ShaiHuludDetector](http://_vscodecontentref_/5)

- **[__init__](http://_vscodecontentref_/6)**: Initializes the detector with token, org name, headers, indicators, and logging.
- **[setup_logging](http://_vscodecontentref_/7)**: Configures error, debug, and info loggers.
- **[log_finding](http://_vscodecontentref_/8)**: Appends a detection finding to the results list.
- **[identify_campaign](http://_vscodecontentref_/9)**: Classifies the finding by attack campaign (CrowdStrike, Shai-Hulud, etc.).
- **[make_github_request](http://_vscodecontentref_/10)**: Makes authenticated GitHub API requests with rate limit handling.
- **[scan_malicious_repositories](http://_vscodecontentref_/11)**: Searches for malicious repo names/descriptions.
- **[scan_malicious_branches](http://_vscodecontentref_/12)**: Checks all repos for branches named `shai-hulud`.
- **[scan_malicious_workflows](http://_vscodecontentref_/13)**: Looks for malicious workflow files and suspicious workflow names.
- **[scan_package_files](http://_vscodecontentref_/14)**: Scans for compromised npm packages and suspicious postinstall scripts.
- **[scan_malicious_files](http://_vscodecontentref_/15)**: Searches for malicious `bundle.js` files by hash and content.
- **[scan_for_ai_patterns](http://_vscodecontentref_/16)**: Flags files with AI-generated code patterns and malicious content.
- **[run_comprehensive_scan](http://_vscodecontentref_/17)**: Runs all detection modules sequentially, logs summary.
- **[export_to_csv](http://_vscodecontentref_/18)**: Exports all findings to a CSV file.

### [main()](http://_vscodecontentref_/19)

- Parses arguments, runs the detector, exports results, and prints summary/remediation steps.

---

## Output

- **CSV Report:**  
  - Contains timestamp, org, repo, finding type, severity, details, file path, hash, URL, campaign, status, and additional data.
- **Logs:**  
  - Debug logs: `logs/debug/`
  - Error logs: `logs/error/`

---

## Mitigation & Response

If any **CRITICAL** findings are detected:
1. **Rotate all credentials immediately**
2. **Remove malicious repositories, branches, and workflows**
3. **Check production applications for compromised npm packages**
4. **Monitor for connections to exfiltration endpoints (`webhook.site`, `5.199.166.1`)**
5. **Review all recent commits and package updates since September 2025**

---

## References

- [NPM Package Malware CrowdStrike Attack Information (PDF)](NPM%20Package%20Malware%20CrowdStrike%20Attack%20Information%20[Detection,%20Mitigation,%20Potential%20Risks].pdf)
- [Official GitHub API Documentation](https://docs.github.com/en/rest)

---
