# Azure DevOps to GitHub Migration Tool

A comprehensive toolkit for migrating repositories from Azure DevOps (ADO) to GitHub. This tool supports two migration approaches:
- Migration with team assignments
- Migration without team assignments

## Features

- Batch migration of repositories from ADO to GitHub
- CSV-based repository tracking and error logging
- Support for team permissions migration
- Post-migration validation tools
- Detailed error reporting and recovery options

## Prerequisites

### GitHub CLI Installation
For Ubuntu/Debian-based systems:
```bash
type -p curl >/dev/null || (sudo apt update && sudo apt install curl -y)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
&& sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
&& sudo apt update \
&& sudo apt install gh -y
```

### GitHub CLI Extension
```bash
gh extension install github/gh-ado2gh
```

## Configuration

### Environment Variables
Set the following environment variables:
```bash
export GH_PAT="your_github_personal_access_token"  # Must be a classic token
export ADO_PAT="your_azure_personal_access_token"
```

### GitHub Authentication
```bash
gh auth login
```

## Usage

### Migration with Team Assignment

1. Extract the migration package:
```bash
unzip MigrationWithAssigningTeam.zip
```

2. Set up execution permissions:
```bash
chmod +x ./MigrationWithAssigningTeam/migrationWithAssigningTeam.sh
```

3. Run the migration:
```bash
cd MigrationWithAssigningTeam
./migrationWithAssigningTeam.sh
```

### Migration without Team Assignment

1. Extract the migration package:
```bash
unzip MigrationWithoutAssigningTeam.zip
```

2. Set up execution permissions:
```bash
chmod +x ./MigrationWithoutAssigningTeam/migrationWithoutAssigningTeam.sh
```

3. Run the migration:
```bash
cd MigrationWithoutAssigningTeam
./migrationWithoutAssigningTeam.sh
```

## Project Structure

- `MigrationWithAssigningTeam/` - Scripts and configs for team-aware migration
- `MigrationWithoutAssigningTeam/` - Scripts for basic repository migration
- `checkAfterMigration/` - Post-migration validation tools

## Input Files

- `latestCommitInfo.csv` - Source repository list with commit information
- `latestCommitInfoProjectRepoNames.csv` - Processed repository data

## Output Files

- `error_log.csv` - Migration error reports
- `migrationFailedToTheseRepositories.csv` - Failed migration attempts
- `orgRepositories.csv` - Successfully migrated repositories

## Validation

Use the checker tools in `checkAfterMigration/` to verify successful migrations:
```bash
cd MigrationWithoutAssigningTeam/checkAfterMigration
./checkForTheReposWhenMigrationFailed.sh
```

## Troubleshooting

1. Verify environment variables are set correctly
2. Check error logs in `error_log.csv`
3. Run validation scripts to identify failed migrations
4. Ensure GitHub CLI is authenticated
