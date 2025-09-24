#!/usr/bin/env python3

import requests
import csv
import json
from datetime import datetime
import time
import sys

class ShaiHuludScanner:
    def __init__(self, token, org_name):
        self.token = token
        self.org_name = org_name
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.findings = []
        
    def log_finding(self, repo_name, issue_type, details, severity="HIGH"):
        """Log a finding to the results list"""
        self.findings.append({
            'Repository': repo_name,
            'Issue_Type': issue_type,
            'Details': details,
            'Severity': severity,
            'Date_Found': datetime.now().isoformat(),
            'Status': 'DETECTED'
        })
        
    def api_request(self, url, params=None):
        """Make API request with rate limit handling"""
        try:
            response = requests.get(url, headers=self.headers, params=params)
            
            # Handle rate limiting
            if response.status_code == 403 and 'rate limit' in response.text.lower():
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                wait_time = reset_time - int(time.time()) + 1
                print(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                return self.api_request(url, params)
                
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            return None
            
    def scan_malicious_repositories(self):
        """Scan for repositories named 'Shai-Hulud' or with migration description"""
        print("🔍 Scanning for malicious repositories...")
        
        # Search for Shai-Hulud repositories
        url = "https://api.github.com/search/repositories"
        params = {'q': f'Shai-Hulud org:{self.org_name}'}
        
        results = self.api_request(url, params)
        if results and results.get('items'):
            for repo in results['items']:
                self.log_finding(
                    repo['name'],
                    'MALICIOUS_REPOSITORY',
                    f"Repository named 'Shai-Hulud' found - likely data exfiltration repository",
                    "CRITICAL"
                )
                
        # Search for migration repositories
        params = {'q': f'"Shai-Hulud Migration" org:{self.org_name}'}
        results = self.api_request(url, params)
        if results and results.get('items'):
            for repo in results['items']:
                self.log_finding(
                    repo['name'],
                    'MIGRATION_REPOSITORY',
                    f"Repository with 'Shai-Hulud Migration' description found",
                    "CRITICAL"
                )
                
    def scan_malicious_branches(self):
        """Scan all repositories for malicious branches"""
        print("🔍 Scanning for malicious branches...")
        
        # Get all organization repositories
        repos_url = f"https://api.github.com/orgs/{self.org_name}/repos"
        repos = self.api_request(repos_url, {'per_page': 100})
        
        if not repos:
            return
            
        for repo in repos:
            repo_name = repo['name']
            
            # Get branches for each repository
            branches_url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/branches"
            branches = self.api_request(branches_url)
            
            if branches:
                for branch in branches:
                    if branch['name'].lower() == 'shai-hulud':
                        self.log_finding(
                            repo_name,
                            'MALICIOUS_BRANCH',
                            f"Branch 'shai-hulud' found",
                            "HIGH"
                        )
                        
    def scan_malicious_workflows(self):
        """Scan for malicious GitHub Actions workflows"""
        print("🔍 Scanning for malicious workflows...")
        
        repos_url = f"https://api.github.com/orgs/{self.org_name}/repos"
        repos = self.api_request(repos_url, {'per_page': 100})
        
        if not repos:
            return
            
        for repo in repos:
            repo_name = repo['name']
            
            # Get workflows for each repository
            workflows_url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/actions/workflows"
            workflows = self.api_request(workflows_url)
            
            if workflows and workflows.get('workflows'):
                for workflow in workflows['workflows']:
                    if 'shai-hulud' in workflow['name'].lower():
                        self.log_finding(
                            repo_name,
                            'MALICIOUS_WORKFLOW',
                            f"Suspicious workflow found: {workflow['name']}",
                            "HIGH"
                        )
                        
    def scan_suspicious_code(self):
        """Scan for suspicious code patterns"""
        print("🔍 Scanning for suspicious code patterns...")
        
        suspicious_patterns = [
            'bundle.js',
            'webhook.site',
            'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7',
            'TruffleHog',
            'postinstall curl',
            'postinstall wget'
        ]
        
        for pattern in suspicious_patterns:
            url = "https://api.github.com/search/code"
            params = {'q': f'{pattern} org:{self.org_name}'}
            
            results = self.api_request(url, params)
            if results and results.get('items'):
                for item in results['items']:
                    self.log_finding(
                        item['repository']['name'],
                        'SUSPICIOUS_CODE',
                        f"Suspicious pattern '{pattern}' found in {item['path']}",
                        "MEDIUM"
                    )
                    
    def scan_recent_commits(self):
        """Scan for suspicious recent commits since attack start date"""
        print("🔍 Scanning recent commits since September 14, 2025...")
        
        repos_url = f"https://api.github.com/orgs/{self.org_name}/repos"
        repos = self.api_request(repos_url, {'per_page': 100})
        
        if not repos:
            return
            
        for repo in repos:
            repo_name = repo['name']
            
            # Get commits since attack start date
            commits_url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/commits"
            params = {'since': '2025-09-14T00:00:00Z'}
            
            commits = self.api_request(commits_url, params)
            if commits:
                for commit in commits:
                    commit_msg = commit['commit']['message'].lower()
                    if any(keyword in commit_msg for keyword in ['bundle', 'postinstall', 'shai-hulud']):
                        self.log_finding(
                            repo_name,
                            'SUSPICIOUS_COMMIT',
                            f"Suspicious commit: {commit['sha'][:8]} - {commit['commit']['message'][:100]}",
                            "MEDIUM"
                        )
                        
    def export_to_csv(self, filename='shai_hulud_scan_results.csv'):
        """Export findings to CSV"""
        if not self.findings:
            print("No findings to export.")
            return
            
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['Repository', 'Issue_Type', 'Details', 'Severity', 'Date_Found', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding)
                
        print(f"Results exported to {filename}")
        
    def run_full_scan(self):
        """Run complete scan"""
        print(f"🚀 Starting Shai-Hulud scan for organization: {self.org_name}")
        print("="*60)
        
        try:
            self.scan_malicious_repositories()
            self.scan_malicious_branches()
            self.scan_malicious_workflows()
            self.scan_suspicious_code()
            self.scan_recent_commits()
            
            print("="*60)
            print(f"✅ Scan completed. Found {len(self.findings)} potential issues.")
            
            # Print summary
            if self.findings:
                print("\n📊 Summary:")
                severity_counts = {}
                for finding in self.findings:
                    severity = finding['Severity']
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                for severity, count in severity_counts.items():
                    print(f"   {severity}: {count}")
                    
                print(f"\n🔍 First 5 findings:")
                for finding in self.findings[:5]:
                    print(f"   - {finding['Repository']}: {finding['Issue_Type']} - {finding['Details'][:80]}...")
            
            # Export results
            self.export_to_csv(filename=f'{self.org_name}_scanned_results.csv')
            
        except Exception as e:
            print(f"Error during scan: {e}")
            

def main():
    """Main function"""
    if len(sys.argv) != 3:
        print("Usage: python shai_hulud_scanner.py <GITHUB_TOKEN> <ORG_NAME>")
        print("Example: python shai_hulud_scanner.py ghp_xxxxxxxxxxxx myorganization")
        sys.exit(1)
        
    token = sys.argv[1]
    org_name = sys.argv[2]
    
    scanner = ShaiHuludScanner(token, org_name)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()