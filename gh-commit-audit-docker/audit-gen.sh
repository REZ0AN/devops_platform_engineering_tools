#!/bin/sh


# Source the environment variables
if [ -f .env ]; then
    . ./.env
fi

## use environment variable ORG_NAME to set the organization name
# If ORG_NAME is not set, it will default to 'your-org-name'
ORG_NAME="${ORG_NAME:-your-org-name}"
# If TEAM_ID is not set, it will default to 'your-team-id'
TEAM_ID="${TEAM_ID:-your-team-id}"
## Getting the Data We Need To Process Further
python3 get-data.py "$ORG_NAME" "$TEAM_ID"

## Now two files will be generated repos.txt and team_users.txt


## Use environment variable with detfault values to set iIS_PERIOD and MONTH_START, MONTH_END, PERIOD
# Set Period if you want to set a period for the audit instead of month range
# 0 for month range and 1 for period

IS_PERIOD="${IS_PERIOD:-0}"

# Set the month range for the audit
# month has to be in this format  YYYY-MM
# for example 2025-01

# The months for which the audit is being generated
# You can change the month as per your requirement
# Got the values from the environment variable or set default values
# If MONTH_START is not set, it will default to '2025-01'
# If MONTH_END is not set, it will default to '2025-02'
# If you set IS_PERIOD to 1 then MONTH_END will be ignored
MONTH_START="${MONTH_START:-2025-01}"
MONTH_END="${MONTH_END:-2025-02}"


# if you set is_period to 1 then you have to set the period
## Got the value from the environment variable or set default value
# If PERIOD is not set, it will default to '3' (3 months)
# This means the audit will be generated for the last 3 months from the start month
PERIOD="${PERIOD:-3}"

## Auditing Based on Team name and User Under the team and also in the filtered list of 
## repositories by Custom_Properties Audit Field

while IFS='=' read -r TEAM_NAME USERNAMES; do
    # Remove leading/trailing whitespace from USERNAME
    USERNAMES=$(echo "$USERNAMES" | xargs)
    # Call the Python script for auditing with "$USERNAMES" "$MONTH_START" "$MONTH_END" "$TEAM_NAME" "$IS_PERIOD" "$PERIOD"  as arguments
    python3 monthly-audit.py "$USERNAMES" "$MONTH_START" "$MONTH_END" "$TEAM_NAME" "$IS_PERIOD" "$PERIOD"
    ## TODO : mailx setup
done < team_users.txt


