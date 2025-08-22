import requests
import sys
import os
from datetime import datetime
import logging



BASE_URL="http://10.100.6.201:8000/api/git"

## get the current directory
c_dir = os.path.dirname(os.path.realpath(__file__))

Type = "api-git-internal-api"
## ensuring if the error.log file exists or not
if not os.path.exists(f'{c_dir}/error-{Type}-{datetime.now().strftime("%Y-%m-%d %H:%M")}.log'):
    with open(f'{c_dir}/error-{Type}-{datetime.now().strftime("%Y-%m-%d %H:%M")}.log', 'w'):
        pass

## configure logging file
logging.basicConfig(filename=f'{c_dir}/error-{Type}-{datetime.now().strftime("%Y-%m-%d %H:%M")}.log',level=logging.ERROR,format='%(asctime)s - %(levelname)s - %(message)s')



def formatUsers(team_users):
    results = []
    for key, array in team_users.items():
        logins = " ".join(item["login"] for item in array)
        results.append(f"{key}={logins}")
    return results

def getUserList(org_name, team_id):
    try :
        url = f"{BASE_URL}/sod-user-list"
        params = {
            "org_name":org_name,
            "team_id":team_id
        }
        print('[INFO] Fetching user-lists ', org_name, team_id)
        response = requests.get(url, params=params)
        if response.status_code == 200:
            results = response.json()
            team_users = formatUsers(results)
            with open(f"{c_dir}/team_users.txt", 'w') as file:
                file.write("\n".join(team_users) + '\n')
            return True
        else:
            response.raise_for_status()
    except Exception as e :
            print(f"[error] failed to fetch users of a team {team_id} in org {org_name}")
            logging.error(f"Error occurred while fetching users from org {org_name} in team_id {team_id}: {e}")
            return False
    
def getRepoDetails(org_name, repo_name):
    try :
        url = f"{BASE_URL}/repo-details"
        params = {
            "org_name":org_name,
            "repo_name":repo_name,
        }
        print('[INFO] Fetching repo-details ', repo_name)
        response = requests.get(url, params=params)
        if response.status_code == 200:
            repoDetails = response.json()

            return repoDetails
        else:
            response.raise_for_status()
    except Exception as e :
            print("[error] failed to get repository details")
            logging.error(f"Error occurred while fetching repo-details from org {org_name} repo {repo_name} : {e}")
            return None  

def isAuditNeeded(repo_details) :
       return repo_details['custom_properties']['Audit'] == 'Yes'

def getfilteredRepositories(repos, org_name):
    repoLinks = []
    for repo in repos :
        repoDetails = getRepoDetails(org_name, repo['name'])
        if repoDetails is not None  and isAuditNeeded(repoDetails):
                repoLinks.append(f'{repo['html_url']}.git')
    return repoLinks

def getRepoList(org_name):
    try :
        url = f"{BASE_URL}/repo-list"
        params = {
            "org_name":org_name
        }
        print('[INFO] Fetching repo-lists ', org_name)
        response = requests.get(url, params=params)
        if response.status_code == 200:
            repos = response.json()
            repoLinks = getfilteredRepositories(repos, org_name)
            with open(f"{c_dir}/repos.txt", 'w') as file:
                file.write("\n".join(repoLinks) + '\n')
            return True
        else:
            response.raise_for_status()
    except Exception as e :
            print('[error] failed to list repos', org_name)
            logging.error(f"Error occurred while fetching repos from org {org_name} : {e}")
            return False
        
if __name__ == "__main__":
     
    # Get the usernames passed as an argument
    if len(sys.argv) < 3:
        print("[ERROR] program argument not provided expected two argument 1st ORG_NAME 2nd TEAM_ID")
        sys.exit(1)

    # extracting the orgName
    orgName = sys.argv[1]
    # extracting the teamId
    teamId = sys.argv[2]
    

    if getRepoList(orgName) == True :
          print('[success] repos.txt file successfully populated with filtered data')
    if getUserList(orgName, teamId) == True :
          print('[success] team_users.txt file successfully populated with users data')

