# GitHub Organization Repository Commit Audit Tool

A tool to generate monthly audit reports of repository commits by members and contributors across your GitHub organization.

## Prerequisites

- Python 3.10
- `mailx` utility configured for email distribution
- GitHub Personal Access Token
- Required Python packages (specified in requirements.txt)

## Installation

1. Clone this repository or download the files to your target directory
2. Install the required Python packages:
   ```bash
   pip3 install -r requirements.txt
   ```
3. Configure your GitHub Personal Access Token:
   ```bash
   export GH_PAT="your_github_token"
   ```

## Configuration

### Email Distribution Setup

Edit `audit-gen-with-mailing.sh` to configure email recipients:
- Add email addresses (space-separated) to the `MAILUSERS` variable

### Audit Period Configuration

The tool supports two modes of operation:

1. **Period-based Audit**
   - Set `is_period=1`
   - Configure:
     - `MONTH_START`: Starting month
     - `PERIOD`: Number of months to audit

2. **Date Range Audit**
   - Set `is_period=0`
   - Configure:
     - `MONTH_START`: Start month of range
     - `MONTH_END`: End month of range

## Usage

1. Make the script executable:
   ```bash
   chmod +x ./audit-gen-with-mailing.sh
   ```

2. Run the audit:
   ```bash
   ./audit-gen-with-mailing.sh
   ```

## Output

The script generates CSV files in the following format:
`<Team_Name>-<Month_Start>-to-<Month_End>-audit.csv`

These reports are automatically:
- Generated in the current directory
- Sent to the configured email distribution list
