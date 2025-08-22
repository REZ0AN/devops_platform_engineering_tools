# GitHub Commit Audit Tool

A containerized solution for generating commit audit reports across GitHub organizations. This tool allows you to analyze commit patterns within specified date ranges or periods across teams and repositories.

## Prerequisites

- Docker installed on your system
- GitHub Personal Access Token with appropriate permissions
- Organization Admin access or appropriate team permissions

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/REZ0AN/devops_platform_engineering_tools.git
cd gh-commit-audit-docker
```

2. Create required directories:
```bash
mkdir -p ./audits ./logs/error
```

3. Configure environment variables:

Create a `.env` file in the project root with the following configuration:
```bash
ORG_NAME=<your-organization-name>
TEAM_ID=<your-team-id>
MONTH_START=2024-01
MONTH_END=2024-02
IS_PERIOD=0
PERIOD=3
GH_PAT=<your-github-personal-access-token>
```

## Configuration Options

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ORG_NAME` | GitHub Organization name | None | Yes |
| `TEAM_ID` | Team identifier for filtering | None | Yes |
| `MONTH_START` | Start month (YYYY-MM format) | None | Yes |
| `MONTH_END` | End month (YYYY-MM format) | None | If IS_PERIOD=0 |
| `IS_PERIOD` | Enable period-based auditing | 0 | If period based auditing needed |
| `PERIOD` | Number of months to audit | 3 | If IS_PERIOD=1 |
| `GH_PAT` | GitHub Personal Access Token | None | Yes |

## Usage

1. Build the Docker image:
```bash
docker build -t gh-audit .
```

2. Run the audit:
```bash
docker run --env-file .env \
  -v $(pwd)/audits:/app/audits \
  -v $(pwd)/logs:/app/logs \
  gh-audit
```

## Output

- Audit reports are generated in the `./audits` directory
- Log files are stored in `./logs` directory
- Error logs can be found in `./logs/error`

## Troubleshooting

1. Check error logs:
```bash
cat ./logs/error/*.log
```

2. Common issues:
   - Empty audit files: Verify GitHub token permissions
   - No output: Check logs for API rate limiting
   - Container exits: Ensure valid environment variables

## Security Notes

- Store your `.env` file securely and never commit it to version control
- Use GitHub tokens with minimum required permissions
- Regularly rotate your GitHub Personal Access Token
