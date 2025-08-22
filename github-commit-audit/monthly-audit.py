import requests
import pandas as pd
import numpy as np
import sys
import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
import logging
import calendar
import time

BASE_URL="https://api.github.com"

## get the current directory
c_dir = os.path.dirname(os.path.realpath(__file__))

## ensuring if the error.log file exists or not
if not os.path.exists(f'{c_dir}/error-{type}-{datetime.now().strftime("%Y-%m-%d %H:%M")}.log'):
    with open(f'{c_dir}/error-{type}-{datetime.now().strftime("%Y-%m-%d %H:%M")}.log', 'w'):
        pass

## configure logging file
logging.basicConfig(filename=f'{c_dir}/error-{type}-{datetime.now().strftime("%Y-%m-%d %H:%M")}.log',level=logging.ERROR,format='%(asctime)s - %(levelname)s - %(message)s')


def get_user_commits(config, user):
    """Fetch the commits by a user in a repository."""
    commits = []
    url = f"{BASE_URL}/repos/{config['ORG_NAME']}/{config['REPO_NAME']}/commits"
    params = {
        "author": user,
        "since": config["SINCE"],
        "until": config["UNTIL"]
    }

    print('[INFO] Fetching commits for user:', user)
    response = requests.get(url, headers=config['HEADERS'], params=params)

    df = pd.DataFrame()
    
    if response.status_code == 200:
        commits = response.json()
        if commits == []:
            print(f'[Warning] {user} may not a contibutor to the repository')
            return df
        for commit in commits:
            commit_data = {
                'organization_name': config['ORG_NAME'],
                'repository_name': config['REPO_NAME'],
                'user': user,
                'commit_sha': commit['sha'],
                'commit_date': commit['commit']['author']['date'],
                'commit_message': commit['commit']['message']
            }
            n_df = pd.DataFrame([commit_data])
            df = pd.concat([df,n_df],ignore_index=True)
        print(f'[SUCCESS] Commits fetched for user {user}')
        return df
    else:
        response.raise_for_status()

def audit_commits(config,users):

    """Audit Commits By username in a repository to a csv file."""
    df = pd.DataFrame()

    for user in users:
        try:
            commits = get_user_commits(config,user)
            df = pd.concat([df,commits],ignore_index=True)
            time.sleep(5)
        except Exception as e:
            print(f'[ERROR] Error occurred while fetching commits for user {user} in repository {config["REPO_NAME"]}: {e}')
            logging.error(f"Error occurred while fetching commits for user {user} in repository {repo}: {e}")
            continue
    df.drop_duplicates(inplace=True)
    return df


# Save the DataFrame to a CSV file with custom text
def save_csv_with_meta_info(dataframe, filename, meta_info):
    # Open the file in write mode
    with open(filename, 'w') as f:
        # Write the custom text first
        f.write(meta_info)
        
        # Now write the DataFrame to the file
        dataframe.to_csv(f, index=False)

if __name__ == "__main__":

    # Get the usernames passed as an argument
    if len(sys.argv) < 7:
        print("[ERROR] program argument not provided expected three argument 1st USERNAMES 2nd MONTH_START 3rd MONTH_END 4th TEAM_NAME 5th is_period 6th PERIOD")
        sys.exit(1)

    # extracting the username
    usernames_ = sys.argv[1]
    # extracting the start month
    MONTH_START = sys.argv[2]
    # extracting the end month
    MONTH_END = sys.argv[3]
    # extracting the team_name
    TEAM_NAME = sys.argv[4]
    # extracting the is_period
    is_period = int(sys.argv[5])
    # extracting the period
    PERIOD = int(sys.argv[6])


    # creating datetime object
    start_month = datetime.strptime(MONTH_START, '%Y-%m')
    if is_period == 1:
        # get the end month in datetime format
        end_month = start_month - relativedelta(months=PERIOD)
        MONTH_END = end_month.strftime('%Y-%m')
        MONTH_START, MONTH_END = MONTH_END, MONTH_START
        start_month, end_month = end_month, start_month
    else:
        # get the end month in datetime format
        end_month = datetime.strptime(MONTH_END, '%Y-%m')
        MONTH_END = end_month.strftime('%Y-%m')
    
    # Split the string into a list 
    usernames = usernames_.split()

    # get the github access token
    TOKEN = os.environ.get('GH_PAT')

    # get the current month

    # defining the header for REST-API get request
    HEADERS = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {TOKEN}",
                "X-GitHub-Api-Version": "2022-11-28"
            }
    
    # extracting the first day and last day of the current month
    _, last_day_of_month = calendar.monthrange(end_month.year, end_month.month)
    SINCE = f"{MONTH_START}-01T00:00:00Z"
    UNTIL = f"{MONTH_END}-{last_day_of_month}T23:59:59Z"

    # config dictionary 
    config = {
        "TOKEN":TOKEN,
        "HEADERS":HEADERS,
        "SINCE":SINCE,
        "UNTIL":UNTIL,
    }

    with open(f'{c_dir}/repos.txt') as f:
        repos = f.read().splitlines()

    ## exported data collection
    all_Df = pd.DataFrame()
    print(f'[INFO] Starting audit for {TEAM_NAME} from {MONTH_START} to {MONTH_END}')
    ## visiting all repositories to find out the contributions
    for repo in repos:
        try:    
            # extracting organization name and repository name from the repository link
            ORG_NAME = repo.split("/")[-2]
            REPO_NAME = repo.split("/")[-1].split(".")[0]
            # adding them to config
            config["ORG_NAME"]=ORG_NAME
            config["REPO_NAME"]=REPO_NAME

            # get audit for repo
            df = audit_commits(config,usernames)

            # concat the results for the global data collection
            all_Df = pd.concat([all_Df,df],ignore_index=True)

        except Exception as e:
            logging.error(f"Error occurred while auditing repository {repo}: {e}")
            continue


    filename = f"{c_dir}/{TEAM_NAME}-{MONTH_START}-to-{MONTH_END}-audit.csv"
    # meta info to be added before the header
    meta_info = f'\n\nAudit Report from {MONTH_START} to {MONTH_END}\n\nTeam_Name:{TEAM_NAME}\n\n'
    save_csv_with_meta_info(all_Df, filename, meta_info)
    print(f'[SUCCESS] Audit report generated for {TEAM_NAME} from {MONTH_START} to {MONTH_END} in {c_dir}/{TEAM_NAME}-{MONTH_START}-to-{MONTH_END}-audit.csv')
