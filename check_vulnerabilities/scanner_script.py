#!/usr/bin/env python3
"""
Shai-Hulud Malware Detection CSV Generator
Comprehensive async scanner for npm supply chain attacks with CSV output
"""

import asyncio
import aiohttp
import aiofiles
import csv
import json
import hashlib
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import base64
import re

class ShaiHuludDetector:
    def __init__(self, github_token: str, org_name: str):
        self.github_token = github_token
        self.org_name = org_name
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Shai-Hulud-Detector/1.0'
        }
        
        # Setup logging
        self.setup_logging()
        
        # Detection results
        self.findings = []
        
        # Malicious indicators from multi-source intelligence
        self.malicious_hashes = {
            "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09": "CrowdStrike variant",
            "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777": "Unit42 confirmed",
            "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c": "Shai-Hulud V3",
            "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db": "Shai-Hulud V4",
            "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6": "Shai-Hulud V1",
            "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3": "Shai-Hulud V2",
            "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e": "Shai-Hulud V5"
        }
        
        self.compromised_packages = [
            "@ctrl/tinycolor", "@ctrl/deluge", "@ctrl/golang-template", "@ctrl/magnet-link",
            "@ctrl/ngx-codemirror", "@ctrl/ngx-csv", "@ctrl/ngx-emoji-mart", "@ctrl/ngx-rightclick",
            "@ctrl/qbittorrent", "@ctrl/react-adsense", "@ctrl/shared-torrent", "@ctrl/torrent-file",
            "@ctrl/transmission", "@ctrl/ts-base32",
            "@crowdstrike/commitlint", "@crowdstrike/glide-core", "@crowdstrike/logscale-dashboard",
            "@crowdstrike/logscale-file-editor", "@crowdstrike/logscale-parser-edit", 
            "@crowdstrike/logscale-search", "@crowdstrike/falcon-shoelace", "@crowdstrike/foundry-js",
            "@crowdstrike/tailwind-toucan-base", "eslint-config-crowdstrike", "remark-preset-lint-crowdstrike",
            "@nativescript-community/gesturehandler", "@nativescript-community/sentry",
            "@nativescript-community/text", "@nativescript-community/ui-collectionview",
            "@nativescript-community/ui-drawer", "@nativescript-community/ui-image",
            "@nativescript-community/ui-material-bottomsheet", "@nativescript-community/ui-material-core",
            "angulartics2", "encounter-playground", "json-rules-engine-simplified", "koa2-swagger-ui",
            "ethers-provider2", "ethers-providerz", "reproduction-hardhat", "@theoretical123/providers"
        ]
        
        self.malicious_domains = [
            "webhook.site",
            "5.199.166.1"
        ]
        
        self.malicious_endpoints = [
            "webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
            "5.199.166.1:31337"
        ]

    def setup_logging(self):
        """Setup logging with separate error and debug folders"""
        # Create log directories
        log_base = Path("logs")
        error_dir = log_base / "error"
        debug_dir = log_base / "debug"
        
        error_dir.mkdir(parents=True, exist_ok=True)
        debug_dir.mkdir(parents=True, exist_ok=True)
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Setup error logger
        self.error_logger = logging.getLogger('shai_hulud_error')
        self.error_logger.setLevel(logging.ERROR)
        error_handler = logging.FileHandler(
            error_dir / f"{self.org_name}_shai_hulud_errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        error_handler.setFormatter(formatter)
        self.error_logger.addHandler(error_handler)
        
        # Setup debug logger
        self.debug_logger = logging.getLogger('shai_hulud_debug')
        self.debug_logger.setLevel(logging.DEBUG)
        debug_handler = logging.FileHandler(
            debug_dir / f"{self.org_name}_shai_hulud_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        debug_handler.setFormatter(formatter)
        self.debug_logger.addHandler(debug_handler)
        
        # Console handler for info
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        self.info_logger = logging.getLogger('shai_hulud_info')
        self.info_logger.setLevel(logging.INFO)
        self.info_logger.addHandler(console_handler)
        self.info_logger.addHandler(debug_handler)  # Also log info to debug file

    def log_finding(self, repo_name: str, finding_type: str, severity: str, 
                   details: str, file_path: str = "", hash_value: str = "", 
                   url: str = "", additional_data: Dict = None):
        """Log a finding to the results list"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'organization': self.org_name,
            'repository': repo_name,
            'finding_type': finding_type,
            'severity': severity,
            'details': details,
            'file_path': file_path,
            'hash_sha256': hash_value,
            'url': url,
            'campaign': self.identify_campaign(finding_type, details),
            'status': 'DETECTED',
            'additional_data': json.dumps(additional_data) if additional_data else ""
        }
        self.findings.append(finding)
        self.debug_logger.debug(f"Finding logged: {finding_type} in {repo_name}")

    def identify_campaign(self, finding_type: str, details: str) -> str:
        """Identify which attack campaign the finding belongs to"""
        if "ethers" in details.lower() or "5.199.166.1" in details:
            return "March 2025 Package Patching"
        elif "crowdstrike" in details.lower():
            return "September 2025 CrowdStrike Expansion"
        elif "shai-hulud" in details.lower() or "webhook.site" in details.lower():
            return "September 2025 Shai-Hulud Worm"
        elif "s1ngularity" in details.lower() or "nx" in details.lower():
            return "August 2025 S1ngularity/Nx"
        else:
            return "Unknown/Generic"

    async def make_github_request(self, session: aiohttp.ClientSession, url: str, 
                                 params: Dict = None) -> Optional[Dict]:
        """Make authenticated GitHub API request with error handling"""
        try:
            self.debug_logger.debug(f"Making GitHub API request to: {url}")
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.1)
            
            async with session.get(url, headers=self.headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    self.debug_logger.debug(f"API request successful: {url}")
                    return data
                elif response.status == 403:
                    self.error_logger.error(f"Rate limit or permission denied: {url}")
                    # Wait for rate limit reset if available
                    reset_time = response.headers.get('X-RateLimit-Reset')
                    if reset_time:
                        wait_time = int(reset_time) - int(datetime.now().timestamp()) + 1
                        if wait_time > 0 and wait_time < 3600:  # Don't wait more than 1 hour
                            self.info_logger.info(f"Rate limited. Waiting {wait_time} seconds...")
                            await asyncio.sleep(wait_time)
                            return await self.make_github_request(session, url, params)
                elif response.status == 404:
                    self.debug_logger.debug(f"Resource not found (404): {url}")
                    return None
                else:
                    self.error_logger.error(f"API request failed with status {response.status}: {url}")
                    return None
        except Exception as e:
            self.error_logger.error(f"Exception during API request to {url}: {str(e)}")
            return None

    async def scan_malicious_repositories(self, session: aiohttp.ClientSession):
        """Scan for repositories with malicious names and descriptions"""
        self.info_logger.info("🔍 Scanning for malicious repositories...")
        
        try:
            # Search for Shai-Hulud repositories
            shai_hulud_url = "https://api.github.com/search/repositories"
            params = {'q': f'Shai-Hulud org:{self.org_name}'}
            
            results = await self.make_github_request(session, shai_hulud_url, params)
            self.info_logger.info(f'Checking ${len(results.get('items'))} repositories')
            if results and results.get('items'):
                for repo in results['items']:
                    self.log_finding(
                        repo['name'],
                        'MALICIOUS_REPOSITORY',
                        'CRITICAL',
                        f"Repository named 'Shai-Hulud' found - likely data exfiltration repository. Created: {repo.get('created_at', 'unknown')}",
                        url=repo['html_url'],
                        additional_data={
                            'created_at': repo.get('created_at'),
                            'updated_at': repo.get('updated_at'),
                            'description': repo.get('description', ''),
                            'private': repo.get('private', False)
                        }
                    )
                    self.info_logger.info(f"🚨 CRITICAL: Found Shai-Hulud repository: {repo['name']}")

            # Search for migration repositories  
            migration_url = "https://api.github.com/search/repositories"
            params = {'q': f'"Shai-Hulud Migration" org:{self.org_name}'}
            
            results = await self.make_github_request(session, migration_url, params)
            if results and results.get('items'):
                for repo in results['items']:
                    self.log_finding(
                        repo['name'],
                        'MIGRATION_REPOSITORY', 
                        'CRITICAL',
                        f"Repository with 'Shai-Hulud Migration' description found - private repo made public",
                        url=repo['html_url'],
                        additional_data={
                            'created_at': repo.get('created_at'),
                            'updated_at': repo.get('updated_at'),
                            'description': repo.get('description', ''),
                            'private': repo.get('private', False)
                        }
                    )
                    self.info_logger.info(f"🚨 CRITICAL: Found migration repository: {repo['name']}")
                    
        except Exception as e:
            self.error_logger.error(f"Error scanning malicious repositories: {str(e)}")

    async def scan_malicious_branches(self, session: aiohttp.ClientSession):
        """Scan all repositories for malicious branches"""
        self.info_logger.info("🔍 Scanning for malicious branches...")
        
        try:
            # Get all organization repositories
            repos_url = f"https://api.github.com/orgs/{self.org_name}/repos"
            repos = await self.make_github_request(session, repos_url, {'per_page': 100})
            
            if not repos:
                self.error_logger.error("Failed to fetch organization repositories")
                return

            for repo in repos:
                repo_name = repo['name']
                self.debug_logger.debug(f"Checking branches for repository: {repo_name}")
                
                # Get branches for each repository
                branches_url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/branches"
                branches = await self.make_github_request(session, branches_url)
                
                if branches:
                    for branch in branches:
                        if branch['name'].lower() == 'shai-hulud':
                            self.log_finding(
                                repo_name,
                                'MALICIOUS_BRANCH',
                                'HIGH',
                                f"Branch 'shai-hulud' found - malicious branch used for workflow injection",
                                additional_data={
                                    'branch_name': branch['name'],
                                    'commit_sha': branch.get('commit', {}).get('sha', ''),
                                    'protected': branch.get('protected', False)
                                }
                            )
                            self.info_logger.info(f"🚨 HIGH: Found malicious branch in {repo_name}")
                            
        except Exception as e:
            self.error_logger.error(f"Error scanning malicious branches: {str(e)}")

    async def scan_malicious_workflows(self, session: aiohttp.ClientSession):
        """Scan for malicious GitHub Actions workflows"""
        self.info_logger.info("🔍 Scanning for malicious workflows...")
        
        try:
            # Get all organization repositories
            repos_url = f"https://api.github.com/orgs/{self.org_name}/repos"
            repos = await self.make_github_request(session, repos_url, {'per_page': 100})
            
            if not repos:
                return

            for repo in repos:
                repo_name = repo['name']
                self.debug_logger.debug(f"Checking workflows for repository: {repo_name}")
                
                # Check for specific malicious workflow files
                malicious_workflows = [
                    'shai-hulud-workflow.yml',
                    'shai-hulud.yaml', 
                    'shai-hulud-workflow.yaml'
                ]
                
                for workflow_name in malicious_workflows:
                    workflow_url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/contents/.github/workflows/{workflow_name}"
                    workflow_content = await self.make_github_request(session, workflow_url)
                    
                    if workflow_content:
                        # Decode workflow content
                        try:
                            content = base64.b64decode(workflow_content['content']).decode('utf-8')
                            
                            self.log_finding(
                                repo_name,
                                'MALICIOUS_WORKFLOW',
                                'CRITICAL',
                                f"Malicious workflow found: {workflow_name} - contains credential exfiltration code",
                                file_path=f".github/workflows/{workflow_name}",
                                hash_value=hashlib.sha256(content.encode()).hexdigest(),
                                additional_data={
                                    'workflow_name': workflow_name,
                                    'file_size': len(content),
                                    'contains_webhook': 'webhook.site' in content,
                                    'contains_secrets': '${{ secrets' in content
                                }
                            )
                            self.info_logger.info(f"🚨 CRITICAL: Found malicious workflow {workflow_name} in {repo_name}")
                            
                        except Exception as decode_error:
                            self.error_logger.error(f"Error decoding workflow content: {decode_error}")
                
                # Also check all workflows for malicious patterns
                workflows_url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/actions/workflows"
                workflows = await self.make_github_request(session, workflows_url)
                
                if workflows and workflows.get('workflows'):
                    for workflow in workflows['workflows']:
                        if any(pattern in workflow['name'].lower() for pattern in ['shai-hulud', 'migration']):
                            self.log_finding(
                                repo_name,
                                'SUSPICIOUS_WORKFLOW',
                                'HIGH',
                                f"Suspicious workflow name detected: {workflow['name']}",
                                file_path=workflow['path'],
                                url=workflow['html_url'],
                                additional_data={
                                    'workflow_id': workflow['id'],
                                    'state': workflow['state'],
                                    'created_at': workflow.get('created_at')
                                }
                            )
                            
        except Exception as e:
            self.error_logger.error(f"Error scanning malicious workflows: {str(e)}")

    async def scan_package_files(self, session: aiohttp.ClientSession):
        """Scan for compromised npm packages in repositories"""
        self.info_logger.info("🔍 Scanning for compromised npm packages...")
        
        try:
            # Get all organization repositories
            repos_url = f"https://api.github.com/orgs/{self.org_name}/repos"
            repos = await self.make_github_request(session, repos_url, {'per_page': 100})
            
            if not repos:
                return

            for repo in repos:
                repo_name = repo['name']
                self.debug_logger.debug(f"Checking packages for repository: {repo_name}")
                
                # Check package.json files
                package_files = ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']
                
                for package_file in package_files:
                    file_url = f"https://api.github.com/repos/{self.org_name}/{repo_name}/contents/{package_file}"
                    file_content = await self.make_github_request(session, file_url)
                    
                    if file_content:
                        try:
                            content = base64.b64decode(file_content['content']).decode('utf-8')
                            
                            # Check for compromised packages
                            for package in self.compromised_packages:
                                if package in content:
                                    # Try to extract version info
                                    version_match = re.search(f'"{re.escape(package)}".*?"([^"]+)"', content)
                                    version = version_match.group(1) if version_match else "unknown"
                                    
                                    self.log_finding(
                                        repo_name,
                                        'COMPROMISED_PACKAGE',
                                        'HIGH',
                                        f"Compromised package detected: {package}@{version} in {package_file}",
                                        file_path=package_file,
                                        additional_data={
                                            'package_name': package,
                                            'version': version,
                                            'file_type': package_file,
                                            'file_size': len(content)
                                        }
                                    )
                                    self.info_logger.info(f"🚨 HIGH: Found compromised package {package} in {repo_name}")
                            
                            # Check for suspicious postinstall scripts
                            if 'postinstall' in content and any(pattern in content for pattern in ['bundle.js', 'curl', 'wget']):
                                self.log_finding(
                                    repo_name,
                                    'SUSPICIOUS_POSTINSTALL',
                                    'MEDIUM',
                                    f"Suspicious postinstall script found in {package_file}",
                                    file_path=package_file,
                                    additional_data={
                                        'contains_bundle_js': 'bundle.js' in content,
                                        'contains_curl': 'curl' in content,
                                        'contains_wget': 'wget' in content
                                    }
                                )
                                
                        except Exception as decode_error:
                            self.debug_logger.debug(f"Could not decode {package_file} in {repo_name}: {decode_error}")
                            
        except Exception as e:
            self.error_logger.error(f"Error scanning package files: {str(e)}")

    async def scan_malicious_files(self, session: aiohttp.ClientSession):
        """Scan for malicious files by hash and content patterns"""
        self.info_logger.info("🔍 Scanning for malicious files...")
        
        try:
            # Get all organization repositories
            repos_url = f"https://api.github.com/orgs/{self.org_name}/repos"
            repos = await self.make_github_request(session, repos_url, {'per_page': 100})
            
            if not repos:
                return

            for repo in repos:
                repo_name = repo['name']
                self.debug_logger.debug(f"Checking files for repository: {repo_name}")
                
                # Search for bundle.js files specifically
                search_url = f"https://api.github.com/search/code"
                params = {
                    'q': f'filename:bundle.js repo:{self.org_name}/{repo_name}'
                }
                
                search_results = await self.make_github_request(session, search_url, params)
                
                if search_results and search_results.get('items'):
                    for item in search_results['items']:
                        file_url = item['url']
                        file_content = await self.make_github_request(session, file_url)
                        
                        if file_content:
                            try:
                                content = base64.b64decode(file_content['content']).decode('utf-8')
                                content_hash = hashlib.sha256(content.encode()).hexdigest()
                                
                                # Check against known malicious hashes
                                if content_hash in self.malicious_hashes:
                                    variant = self.malicious_hashes[content_hash]
                                    self.log_finding(
                                        repo_name,
                                        'MALICIOUS_FILE_HASH',
                                        'CRITICAL',
                                        f"Malicious bundle.js found - {variant}",
                                        file_path=item['path'],
                                        hash_value=content_hash,
                                        url=item['html_url'],
                                        additional_data={
                                            'variant': variant,
                                            'file_size': len(content)
                                        }
                                    )
                                    self.info_logger.info(f"🚨 CRITICAL: Found malicious bundle.js ({variant}) in {repo_name}")
                                
                                # Check for malicious patterns in content
                                malicious_patterns = [
                                    ('trufflehog', 'Contains TruffleHog credential scanner'),
                                    ('webhook.site', 'Contains webhook.site exfiltration endpoint'),
                                    ('5.199.166.1', 'Contains malicious IP address'),
                                    ('github.com/api/repos', 'Contains GitHub API repository access'),
                                    ('npm publish', 'Contains npm publish commands'),
                                    ('atob(atob(', 'Contains double base64 encoding pattern')
                                ]
                                
                                for pattern, description in malicious_patterns:
                                    if pattern.lower() in content.lower():
                                        self.log_finding(
                                            repo_name,
                                            'SUSPICIOUS_FILE_PATTERN',
                                            'HIGH',
                                            f"Suspicious pattern in bundle.js: {description}",
                                            file_path=item['path'],
                                            hash_value=content_hash,
                                            additional_data={
                                                'pattern': pattern,
                                                'description': description
                                            }
                                        )
                                        
                            except Exception as decode_error:
                                self.debug_logger.debug(f"Could not decode bundle.js in {repo_name}: {decode_error}")
                                
        except Exception as e:
            self.error_logger.error(f"Error scanning malicious files: {str(e)}")

    async def scan_for_ai_patterns(self, session: aiohttp.ClientSession):
        """Scan for AI-generated malware patterns (Unit42 assessment)"""
        self.info_logger.info("🔍 Scanning for AI-generated malware patterns...")
        
        try:
            # Search for JavaScript files with potential AI patterns
            search_url = f"https://api.github.com/search/code"
            params = {
                'q': f'emoji OR "TODO:" OR "NOTE:" extension:js org:{self.org_name}'
            }
            
            search_results = await self.make_github_request(session, search_url, params)
            
            if search_results and search_results.get('items'):
                for item in search_results['items'][:50]:  # Limit to avoid rate limits
                    file_content = await self.make_github_request(session, item['url'])
                    
                    if file_content:
                        try:
                            content = base64.b64decode(file_content['content']).decode('utf-8')
                            
                            # Count AI-like patterns
                            ai_patterns = [
                                '# This script', '# TODO:', '# NOTE:',
                                '// This function', '// NOTE:', '// TODO:',
                                '😀', '😃', '😄', '😁', '😆'
                            ]
                            
                            pattern_count = sum(1 for pattern in ai_patterns if pattern in content)
                            
                            # If high AI pattern density and contains malicious content
                            if pattern_count >= 3:
                                malicious_content = any(pattern in content.lower() for pattern in 
                                                      ['bundle.js', 'webhook.site', 'trufflehog', 'npm publish'])
                                
                                if malicious_content:
                                    self.log_finding(
                                        item['repository']['name'],
                                        'AI_GENERATED_MALWARE',
                                        'HIGH',
                                        f"Potentially AI-generated malicious code detected - {pattern_count} AI patterns",
                                        file_path=item['path'],
                                        hash_value=hashlib.sha256(content.encode()).hexdigest(),
                                        url=item['html_url'],
                                        additional_data={
                                            'ai_pattern_count': pattern_count,
                                            'file_size': len(content),
                                            'contains_malicious': malicious_content
                                        }
                                    )
                                    self.info_logger.info(f"🚨 HIGH: Potential AI-generated malware in {item['repository']['name']}")
                                    
                        except Exception as decode_error:
                            self.debug_logger.debug(f"Could not decode file for AI pattern analysis: {decode_error}")
                            
        except Exception as e:
            self.error_logger.error(f"Error scanning for AI patterns: {str(e)}")

    async def run_comprehensive_scan(self):
        """Run complete malware detection scan"""
        self.info_logger.info(f"🚀 Starting comprehensive Shai-Hulud malware scan for organization: {self.org_name}")
        self.info_logger.info("="*80)
        
        async with aiohttp.ClientSession() as session:
            # Run all detection modules sequentially for reliability
            scan_phases = [
                ("Phase 1/6: Scanning malicious repositories...", self.scan_malicious_repositories),
                ("Phase 2/6: Scanning malicious branches...", self.scan_malicious_branches),
                ("Phase 3/6: Scanning malicious workflows...", self.scan_malicious_workflows),
                ("Phase 4/6: Scanning compromised packages...", self.scan_package_files),
                ("Phase 5/6: Scanning malicious files...", self.scan_malicious_files),
                ("Phase 6/6: Scanning AI-generated patterns...", self.scan_for_ai_patterns)
            ]
            
            successful_phases = 0
            failed_phases = 0
            
            for phase_name, phase_function in scan_phases:
                try:
                    self.info_logger.info(phase_name)
                    await phase_function(session)
                    successful_phases += 1
                    self.debug_logger.debug(f"Completed: {phase_name}")
                except Exception as e:
                    failed_phases += 1
                    self.error_logger.error(f"Failed {phase_name}: {str(e)}")
                    self.info_logger.info(f"⚠️  Phase failed but continuing: {phase_name}")
            
            self.info_logger.info("="*80)
            self.info_logger.info(f"✅ Scan completed. {successful_phases}/{len(scan_phases)} phases successful.")
            self.info_logger.info(f"📊 Found {len(self.findings)} potential issues.")
            
            if failed_phases > 0:
                self.info_logger.info(f"⚠️  {failed_phases} phases failed - check error logs for details")
            
            # Print summary by severity
            severity_counts = {}
            campaign_counts = {}
            
            for finding in self.findings:
                severity = finding['severity']
                campaign = finding['campaign']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                campaign_counts[campaign] = campaign_counts.get(campaign, 0) + 1
            
            if self.findings:
                self.info_logger.info("\n📊 Summary by Severity:")
                for severity, count in sorted(severity_counts.items()):
                    self.info_logger.info(f"   {severity}: {count}")
                
                self.info_logger.info("\n📊 Summary by Campaign:")
                for campaign, count in sorted(campaign_counts.items()):
                    self.info_logger.info(f"   {campaign}: {count}")
                
                self.info_logger.info(f"\n🔍 Top 5 Critical Findings:")
                critical_findings = [f for f in self.findings if f['severity'] == 'CRITICAL'][:5]
                for i, finding in enumerate(critical_findings, 1):
                    self.info_logger.info(f"   {i}. {finding['repository']}: {finding['finding_type']} - {finding['details'][:80]}...")
            else:
                self.info_logger.info("✅ No malware indicators detected in the organization.")

    async def export_to_csv(self, filename: str = None):
        """Export findings to CSV file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.org_name}_shai_hulud_detection_results_{timestamp}.csv"
        
        try:
            if not self.findings:
                self.info_logger.info("No findings to export.")
                return None
            
            fieldnames = [
                'timestamp', 'organization', 'repository', 'finding_type', 'severity',
                'details', 'file_path', 'hash_sha256', 'url', 'campaign', 'status', 'additional_data'
            ]
            
            async with aiofiles.open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # Create CSV content
                csv_content = []
                
                # Write header
                csv_content.append(','.join(fieldnames))
                
                # Write data
                for finding in self.findings:
                    row = []
                    for field in fieldnames:
                        value = str(finding.get(field, ''))
                        # Clean and escape the value
                        value = value.replace('\n', ' ').replace('\r', ' ')
                        if ',' in value or '"' in value or '\n' in value:
                            value = '"' + value.replace('"', '""') + '"'
                        row.append(value)
                    csv_content.append(','.join(row))
                
                # Write all content
                await csvfile.write('\n'.join(csv_content))
            
            self.info_logger.info(f"✅ Results exported to {filename}")
            self.info_logger.info(f"📊 Exported {len(self.findings)} findings across {len(set(f['repository'] for f in self.findings))} repositories")
            return filename
            
        except Exception as e:
            self.error_logger.error(f"Error exporting to CSV: {str(e)}")
            return None

async def main():
    """Main function to run the detector"""
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python shai_hulud_detector.py <GITHUB_TOKEN> <ORG_NAME>")
        print("Example: python shai_hulud_detector.py ghp_xxxxxxxxxxxx myorganization")
        sys.exit(1)
    
    github_token = sys.argv[1]
    org_name = sys.argv[2]
    
    detector = ShaiHuludDetector(github_token, org_name)
    
    try:
        # Run comprehensive scan
        await detector.run_comprehensive_scan()
        
        # Export results to CSV
        csv_filename = await detector.export_to_csv()

        print(f"\n🎯 SCAN COMPLETE!")

        if csv_filename:
            print(f"📄 Results saved to: {csv_filename}")

        print(f"📁 Debug logs: logs/debug/")
        print(f"❌ Error logs: logs/error/")
        print(f"\n🚨 If any CRITICAL findings were detected, take immediate action:")
        print("   1. Rotate all credentials immediately")
        print("   2. Remove malicious repositories and workflows") 
        print("   3. Check production applications for compromised packages")
            
    except Exception as e:
        detector.error_logger.error(f"Fatal error in main: {str(e)}")
        print(f"❌ Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())