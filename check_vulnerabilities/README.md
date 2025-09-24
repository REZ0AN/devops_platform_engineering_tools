# NPM Package Maleware Scanning [initial-version]

## Overview
This tool is designed to scan GitHub organizations for potential indicators of compromise (IoCs) related to the Shai-Hulud NPM supply chain attack that emerged in September 2025. The scanner performs comprehensive checks across repositories, branches, workflows, and code patterns to identify possible compromises.

## Background
The Shai-Hulud attack targeted npm packages by injecting malicious code that exfiltrates sensitive data from compromised systems. The attack was characterized by:
- Creation of malicious repositories named "Shai-Hulud"
- Injection of malicious code into `bundle.js` files
- Use of webhook.site for data exfiltration
- Suspicious postinstall scripts using curl/wget
- Creation of specific migration repositories

## Installation Requirements

```bash
pip install requests
```

## Configuration

1. Create a GitHub Personal Access Token (PAT) with the following permissions:
   - `repo`
   - `read:org`
   - `read:packages`

2. Configure the scanner:

````bash
GH_TOKEN="your_github_pat_here"
ORG_NAME="your_organization_name"

python3 scanner_script.py "$GH_TOKEN" "$ORG_NAME"
````

## Features

### 1. Malicious Repository Detection
- Scans for repositories named "Shai-Hulud"
- Identifies repositories with suspicious migration descriptions
- Severity: CRITICAL

### 2. Malicious Branch Detection
- Identifies branches named "shai-hulud"
- Scans across all organizational repositories
- Severity: HIGH

### 3. Workflow Analysis
- Detects suspicious GitHub Actions workflows
- Identifies workflows containing "shai-hulud" in their names
- Severity: HIGH

### 4. Code Pattern Analysis
Scans for suspicious patterns including:
- `bundle.js` modifications
- webhook.site URLs
- Known malicious UUIDs
- TruffleHog references
- Suspicious postinstall scripts
- Severity: MEDIUM

### 5. Recent Commit Analysis
- Analyzes commits since September 14, 2025
- Focuses on commits containing keywords like:
  - bundle
  - postinstall
  - shai-hulud
- Severity: MEDIUM

## Output

### CSV Export Format
Results are exported to shai_hulud_scan_results.csv with the following fields:
- Repository
- Issue_Type
- Details
- Severity
- Date_Found
- Status

### Console Output
- Real-time scanning progress
- Summary of findings by severity
- First 5 detected issues
- Total number of findings

## Error Handling

The scanner includes:
- Rate limit handling with automatic retry
- API error management
- Exception handling and logging

## Usage Example

```bash
python3 scanner_script.py "ghp_xxxxxxxxxxxx" "myorganization"
```

## Best Practices

1. **Regular Scanning**: Run the scanner daily to detect new compromises
2. **Token Security**: Keep your GitHub PAT secure and rotate regularly
3. **Review Results**: Manually verify all CRITICAL and HIGH severity findings
4. **Backup**: Maintain backups before removing suspected malicious code
5. **Incident Response**: Have an incident response plan ready for positive detections

## Limitations

- Only scans public repositories unless PAT has private repo access
- Rate limiting may affect large organizations
- False positives possible with generic pattern matching
- Limited to GitHub-hosted repositories

## Support

For issues or questions, please:
1. Check the error messages
2. Verify GitHub API access
3. Confirm organization permissions
4. Review PAT scopes

## Security Recommendations

If compromised:
1. Revoke affected credentials
2. Remove malicious code
3. Audit Git history
4. Review GitHub Actions
5. Scan npm dependencies
6. Update security policies

---

*Note: This scanner is part of security response tooling and should be used in conjunction with other security measures.*