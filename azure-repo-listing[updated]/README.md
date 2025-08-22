# Azure Repository Listing Tool

A Python-based utility for generating comprehensive listings of Azure DevOps repositories. This tool helps DevOps teams maintain an updated inventory of their Azure repositories with detailed metadata.

## Features

- Automated repository discovery and listing
- CSV export with repository metadata
- Error logging and reporting
- Support for multiple Azure DevOps organizations
- Configurable output formatting

## Prerequisites

- Python 3.x
- Azure DevOps Personal Access Token (PAT)
- Required Python packages:
    - `pandas`
    - `requests`

## Installation

1. Clone or download this repository
2. Install required Python packages:
```bash
pip install pandas requests
```

3. Set up Azure DevOps authentication:
```bash
export AZURE_DEVOPS_PAT="your_personal_access_token"
```

## Usage

1. Run the repository listing script:
```bash
python3 azureRepoListing.py
```

2. Check the generated output:
   - Repository list: `azure_repo_list[updated].csv`
   - Error log: `error.log`

## Output Format

The `azure_repo_list[updated].csv` contains:
- Repository Name
- Project Name
- Repository URL
- Last Updated Date
- Default Branch
- Size
- Repository State

## Error Handling

All execution errors are logged to `error.log` with:
- Timestamp
- Error type
- Detailed error message
- Stack trace (when applicable)

## File Structure

- `azureRepoListing.py` - Main script for repository listing
- `azure_repo_list[updated].csv` - Output file with repository data
- `error.log` - Error logging file

## Troubleshooting

1. Verify Azure DevOps PAT is correctly set
2. Check `error.log` for detailed error messages
3. Ensure network connectivity to Azure DevOps
4. Verify proper permissions for the PAT