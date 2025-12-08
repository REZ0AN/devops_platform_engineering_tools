# Git Repository Archive Tool

An automated tool for archiving Git repositories. This script processes multiple repositories listed in a text file and archives them according to specified parameters.

## Features

- Batch repository archiving
- Error logging and reporting
- Configurable archive options
- Support for multiple repository sources

## Prerequisites

- Python 3.10

## Configuration

### Repository List
Create a `repo_names.txt` file with one repository URL per line:
```bash
repository_name
```

### Error Logging
Errors are automatically logged to `error.log` with timestamps and detailed information.

## Usage

1. Prepare your repository list in `repo_names.txt`

2. Run the archive script:
```bash
python3 archive-git-repo.py
```

## File Structure

- `archive-git-repo.py` - Main archiving script
- `repo_names.txt` - List of repositories to archive
- `error.log` - Error logging output

## Error Handling

The script automatically handles:
- Invalid repository URLs
- Network connectivity issues
- Permission errors
- Failed archive attempts

All errors are logged to `error.log` with:
- Timestamp
- Error type
- Repository information
- Detailed error message

## Troubleshooting

1. Check `error.log` for detailed error messages
2. Verify repository URLs are correct and accessible
3. Ensure proper Git credentials are configured
4. Verify write permissions in the target directory