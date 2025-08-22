#!/bin/sh

# distribution list for sending mail
MAILUSERS='ahmedabir.rez@gmail.com u1904117@student.cuet.ac.bd'

ORG_NAME="your-org-name"
TEAM_ID="your-team-id"
## Getting the Data We Need To Process Further
python3 get-data.py "$ORG_NAME" "$TEAM_ID"

## Now two files will be generated repos.txt and team_users.txt

# Set Period if you want to set a period for the audit instead of month range
# 0 for month range and 1 for period

is_period='0'

# Set the month range for the audit
# month has to be in this format  YYYY-MM
# for example 2025-01

# The months for which the audit is being generated
# You can change the month as per your requirement
MONTH_START='2025-01'
MONTH_END='2025-02'


# if you set is_period to 1 then you have to set the period
# duration from the start month (if you selected period then MONTH_END will be ignored)
PERIOD='3'

## Auditing Based on Team name and User Under the team and also in the filtered list of 
## repositories by Custom_Properties Audit Field

while IFS='=' read -r TEAM_NAME USERNAMES; do
    # Remove leading/trailing whitespace from USERNAME
    USERNAMES=$(echo "$USERNAMES" | xargs)
    # Call the Python script for auditing with "$USERNAMES" "$MONTH_START" "$MONTH_END" "$TEAM_NAME" "$is_period" "$PERIOD"  as arguments
    python3 monthly-audit.py "$USERNAMES" "$MONTH_START" "$MONTH_END" "$TEAM_NAME" "$is_period" "$PERIOD"

    if [ $? -eq 0 ]; then
    echo "Successfully"
    echo "Monthly Audit Report Team $TEAM_NAME" | mailx -s "Team - $TEAM_NAME Monthly Audit Report" -a $PWD/$TEAM_NAME-$MONTH-audit.csv $MAILUSERS
    fi
done < team_users.txt


