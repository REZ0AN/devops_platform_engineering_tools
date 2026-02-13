# Harness CI - Proof of Concept Setup Guide

A comprehensive step-by-step guide for setting up Harness CI Pipeline with local runner infrastructure instead of Harness Cloud.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Harness Setup](#initial-harness-setup)
   - [Create Harness Account](#step-1-create-harness-account)
   - [Create Project](#step-2-create-harness-project)
   - [Create Delegate Token](#step-3-create-delegate-token)
3. [Source Code Repository Setup](#source-code-repository-setup)
   - [Create GitHub Repository](#step-4-create-github-repository)
   - [Create GitHub Personal Access Token](#step-5-create-github-personal-access-token)
4. [Harness Configuration](#harness-configuration)
   - [Create GitHub Connector](#step-6-create-github-connector)
5. [Local Infrastructure Setup](#local-infrastructure-setup)
6. [Pipeline Creation](#pipeline-creation)
   - [Create Pipeline](#step-7-create-pipeline)
   - [Configure Pipeline YAML](#step-8-configure-pipeline-yaml)
7. [Next Steps](#next-steps)

---

## Prerequisites

Before you begin, ensure you have:

- A GitHub account
- Docker Desktop installed and running (for macOS/Windows) or Docker Engine (for Linux)
- Basic familiarity with Git and YAML
- Terminal/command line access

---

## Initial Harness Setup

### Step 1: Create Harness Account

1. Navigate to https://app.harness.io/
2. Sign up for a free account or log in with existing credentials
3. You'll be redirected to the Harness dashboard upon successful login

---

### Step 2: Create Harness Project

A project in Harness organizes your pipelines, connectors, and other resources.

1. Click **Projects** in the left sidebar
2. Click **+ New Project** (top right corner)
3. Fill in the project details:
   - **Name**: `<your_preferred_project_name>`
   - **Organization**: Select `default` or create a new organization
   - **Description**: `<provide_a_meaningful_description>`
4. Click **Save and Continue**
5. (Optional) Invite collaborators if needed
6. Click **Continue**

**Verification**: You should now see your project in the projects list.

---

### Step 3: Create Delegate Token

Delegate tokens authenticate your local delegate with Harness.

1. Click on **Account Settings** (gear icon at the bottom left)
2. Navigate to **Account Resources** → **Delegates**
3. Click on the **Tokens** tab
4. Click **+ New Token**
5. Enter token details:
   - **Name**: `<descriptive_token_name>` (e.g., `local-delegate-token`)
6. Click **Apply**
7. **IMPORTANT**: Click **Copy** and save the token securely in a text file

**Note**: Also record your **Account ID** (visible at the top of the page) in the same text file. You'll need both values later.

**Example text file:**
```
ACCOUNT_ID: abc123xyz456
DELEGATE_TOKEN: your-copied-token-here
```

---

## Source Code Repository Setup

### Step 4: Create GitHub Repository

1. Log in to your GitHub account at https://github.com
2. Click **New Repository** (or the **+** icon → **New repository**)
3. Configure your repository:
   - **Repository name**: `<your_preferred_repo_name>` (e.g., `harness-ci-demo`)
   - **Visibility**: Public or Private (your choice)
   - **Initialize**: Check **Add a README file** (optional but recommended)
4. Click **Create repository**
5. Note your repository URL: `https://github.com/<username>/<repository_name>`

**Tip**: Add your application code or sample scripts to this repository before proceeding.

---

### Step 5: Create GitHub Personal Access Token

GitHub Personal Access Tokens (PAT) allow Harness to access your repositories.

1. In GitHub, click your **profile picture** → **Settings**
2. Scroll to the bottom → **Developer settings**
3. Click **Personal access tokens** → **Tokens (classic)**
4. Click **Generate new token** → **Generate new token (classic)**
5. Configure the token:
   - **Note**: `<descriptive_name>` (e.g., `harness-ci-token`)
   - **Expiration**: `90 days` or longer based on your preference
   - **Select scopes** (permissions):
     - **repo** (all sub-items) - Full control of private repositories
     - **admin:repo_hook** (all sub-items) - Full control of repository hooks
6. Click **Generate token**
7. **IMPORTANT**: Copy the token immediately and save it in your text file

**Warning**: You won't be able to see this token again. If you lose it, you'll need to create a new one.

---

## Harness Configuration

### Step 6: Create GitHub Connector

Connectors allow Harness to integrate with external services like GitHub.

#### 6.1 Navigate to Connectors

1. In your Harness project, go to **Project Settings** (left sidebar)
2. Under **Project-level resources**, click **Connectors**
3. Click **+ New Connector**

#### 6.2 Select GitHub Connector Type

1. In the right panel that appears, scroll down to **Code Repositories**
2. Click **GitHub**

#### 6.3 Configure Connector Details

**Overview:**
- **Name**: `<descriptive_connector_name>` (e.g., `GitHub-Connector`)
- **URL Type**: Select **Repository**
- **Connection Type**: Select **HTTP**
- **GitHub Repository URL**: `https://github.com/<username>/<repository_name>`

Click **Continue**

#### 6.4 Configure Credentials

**Credentials:**
1. **Authentication**: Select **Username and Token**
2. **Username**: Enter your GitHub username
3. **Personal Access Token**: Click **Create or Select a Secret**

**Creating a Secret in Harness:**
- Click **+ New Secret Text**
- **Secret Name**: `<descriptive_name>` (e.g., `github-pat`)
- **Secret Value**: Paste your GitHub Personal Access Token
- Click **Save**

4. **Enable API access**: Check this box
5. **API Authentication**: Select the secret you just created

Click **Continue**

#### 6.5 Test and Save

1. **Connect through**: Select **Harness Platform**
2. Click **Save and Continue**
3. Wait for the connection test to complete
4. If successful, click **Finish**

**Verification**: The connector should appear in your connectors list with a green checkmark.

---

## Local Infrastructure Setup

Choose your operating system to set up the local delegate and runner:

### [macOS (Apple Silicon M1/M2/M3)](./docs/macos-runner.md)

Follow this guide if you're using a Mac with Apple Silicon chips.

### [Linux (Ubuntu/Debian AMD64)](./docs/linux-runner.md)

Follow this guide if you're using a Linux-based system.

**What you'll set up:**
- Docker Delegate (runs in a container, communicates with Harness)
- Harness Docker Runner (executes your CI builds locally)

---

## Pipeline Creation

### Step 7: Create Pipeline

1. In your Harness project, go to **Pipelines** (left sidebar)
2. Click **+ Create a Pipeline**
3. Enter pipeline details:
   - **Name**: `<your_pipeline_name>` (e.g., `My-CI-Pipeline`)
   - **Setup**: Select **Inline** (stores pipeline in Harness)
4. Click **Start**

### Step 8: Configure Pipeline YAML

Switch to the **YAML** editor and use the following template. Replace placeholders with your actual values.

#### Pipeline YAML Template

```yaml
pipeline:
  name: <your_pipeline_name>                    # e.g., "Python CI Pipeline"
  identifier: <pipeline_identifier>             # e.g., "Python_CI_Pipeline" (no spaces)
  projectIdentifier: <project_identifier>       # Found in project settings
  orgIdentifier: <org_identifier>               # Usually "default"
  tags: {}
  properties:
    ci:
      codebase:
        connectorRef: <github_connector_id>     # ID of GitHub connector created in Step 6
        build: <+input>                         # Prompts for branch at runtime
  stages:
    - stage:
        name: <stage_name>                      # e.g., "Build and Test"
        identifier: <stage_identifier>          # e.g., "Build_and_Test"
        description: ""
        type: CI
        spec:
          cloneCodebase: true                   # Automatically clones your repository
          caching:
            enabled: true                       # Speeds up builds by caching dependencies
            override: true
          buildIntelligence:
            enabled: true                       # Optimizes build execution
          platform:
            os: MacOS                           # Options: MacOS, Linux, Windows
            arch: Arm64                         # Options: Arm64, Amd64
          runtime:
            type: Docker
            spec: {}
          execution:
            steps:
              - step:
                  type: Run
                  name: <step_name>             # e.g., "Run Python Script"
                  identifier: <step_identifier> # e.g., "Run_Python_Script"
                  spec:
                    shell: Sh
                    command: |-
                      echo "Installing Python if needed..."
                      which python3 || brew install python3
                      
                      echo "Running Python script..."
                      python3 hello.py "<+pipeline.name>" "<+pipeline.variables.user_name>: <+pipeline.variables.message>"
        delegateSelectors:                      # Ensures pipeline uses your local delegate
          - <delegate_tag_1>                    # e.g., "darwin-arm64" or "linux-amd64"
          - <delegate_tag_2>                    # e.g., "local-runner"
  variables:
    - name: user_name
      type: String
      description: "Enter your name"
      required: true
      value: <+input>                           # Prompts user at runtime
    - name: message
      type: String
      description: "Enter your message"
      required: true
      value: <+input>                           # Prompts user at runtime
```

#### YAML Configuration Breakdown

| Section | Description | Example Value |
|---------|-------------|---------------|
| `name` | Pipeline display name | `Python CI Pipeline` |
| `identifier` | Unique ID (no spaces) | `Python_CI_Pipeline` |
| `projectIdentifier` | Your project ID | `default_project` |
| `orgIdentifier` | Your organization ID | `default` |
| `connectorRef` | GitHub connector ID | `GitHub_Connector` |
| `platform.os` | Operating system | `MacOS`, `Linux`, `Windows` |
| `platform.arch` | CPU architecture | `Arm64`, `Amd64` |
| `delegateSelectors` | Delegate tags to target | `darwin-arm64`, `linux-amd64` |


#### Finding Your Identifiers

**Project Identifier:**
1. Go to **Project Settings** → **Overview**
2. Copy the **Identifier** field

**Connector Identifier:**
1. Go to **Project Settings** → **Connectors**
2. Click on your GitHub connector
3. Copy the **Identifier** field

**Delegate Tags:**
- Use the tags you set when installing your delegate
- For macOS: `darwin-arm64`, `macos-arm64`, `local-runner`
- For Linux: `linux-amd64`, `local-runner`


#### Sample Complete Pipeline YAML

```yaml
pipeline:
  name: Python Hello World
  identifier: Python_Hello_World
  projectIdentifier: default_project
  orgIdentifier: default
  tags: {}
  properties:
    ci:
      codebase:
        connectorRef: GitHub_Connector
        build: <+input>
  stages:
    - stage:
        name: Build and Run
        identifier: Build_and_Run
        description: "Builds and executes Python application"
        type: CI
        spec:
          cloneCodebase: true
          caching:
            enabled: true
            override: true
          buildIntelligence:
            enabled: true
          platform:
            os: MacOS
            arch: Arm64
          runtime:
            type: Docker
            spec: {}
          execution:
            steps:
              - step:
                  type: Run
                  name: Execute Python Script
                  identifier: Execute_Python
                  spec:
                    shell: Sh
                    command: |-
                      echo "Running on local machine..."
                      python3 --version
                      python3 hello.py "<+pipeline.name>" "<+pipeline.variables.user_name>"
        delegateSelectors:
          - darwin-arm64
          - local-runner
  variables:
    - name: user_name
      type: String
      description: "Your name"
      required: true
      value: <+input>
```


#### Save and Run

1. Click **Save** (top right)
2. Add a commit message: `Initial pipeline configuration`
3. Click **Save**
4. Click **Run** to execute your first build!

**When running:**
- Select the Git branch (e.g., `main`)
- Enter values for any runtime input variables
- Click **Run Pipeline**


## Useful Resources

- **Harness Documentation**: https://developer.harness.io/docs/continuous-integration
- **Community Forum**: https://community.harness.io/
- **Harness University**: https://university.harness.io/
- **GitHub Examples**: https://github.com/harness-community
- **Install Delegate**:
  - https://developer.harness.io/docs/platform/get-started/tutorials/install-delegate/
  - https://developer.harness.io/docs/platform/delegates/install-delegates/overview/
- **Python Run Step**: https://developer.harness.io/docs/continuous-integration/development-guides/ci-python/
- **CI Pipeline Creation**: https://developer.harness.io/docs/continuous-integration/use-ci/prep-ci-pipeline-components/
- **CI Run Steps**: https://developer.harness.io/docs/continuous-integration/use-ci/run-step-settings/
- **Local Runner Infrastructure**: https://developer.harness.io/docs/continuous-integration/use-ci/set-up-build-infrastructure/define-a-docker-build-infrastructure/
- **Email Setup**: https://developer.harness.io/docs/continuous-delivery/x-platform-cd-features/cd-steps/utilities/email-step/
- **SMTP Setup**: https://developer.harness.io/docs/platform/notifications/add-smtp-configuration/


## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Delegate not connecting | Verify Account ID and Token, check delegate logs |
| Pipeline can't find delegate | Ensure `delegateSelectors` match your delegate tags |
| Git clone fails | Verify GitHub connector credentials and repository access |
| Build fails immediately | Check runner is running with `curl http://localhost:3000/healthz` |

### Getting Help

- Check delegate logs: `docker logs <delegate_container_id>`
- Check runner logs: `tail -f runner-log.txt`
- Review pipeline execution logs in Harness UI
- Contact Harness support or community forum
