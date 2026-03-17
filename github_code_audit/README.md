# GitHub Organization LOC Auditor

Counts non-blank, non-comment **Lines of Code (LOC)** for the **largest branch** of every repository in a GitHub organization — no external tools required, works on **macOS, Linux, and Windows**.

The auditor runs in three phases:

| Phase | What it does | Output file |
|---|---|---|
| **1 — Fetch** | Pulls every repo + branch from the GitHub API | `branches.csv` |
| **2 — Measure** | Clones each repo once, measures real disk size of every branch, picks the largest | `branches_sized.csv` |
| **3 — Audit** | Counts LOC only on the largest branch per repo, in batches | `loc_audit.csv` |

Each phase is resumable — if the script is interrupted, re-running it skips already-completed work automatically.

---

## 🛠 Prerequisites

- Python 3.10+
- `git` installed and on your `PATH`
- A [GitHub Personal Access Token](https://github.com/settings/tokens) with `repo` and `read:org` scopes

---

## 🔧 Setup

### macOS / Linux

**1. Clone or copy the project**
```bash
mkdir github_loc_audit
cd github_loc_audit
# copy main.py into this folder
```

**2. Create and activate a virtual environment**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**3. Install dependencies**
```bash
pip install aiohttp tqdm
```

**4. Set environment variables**
```bash
export GITHUB_ORG="your-org-name"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
```

To make them permanent, add the two lines above to your `~/.zshrc` or `~/.bashrc` and run `source ~/.zshrc`.

---

### Windows Server

**1. Open PowerShell as Administrator**

Right-click Start → "Windows PowerShell (Admin)"

**2. Enable TLS 1.2** *(required on Windows Server before any downloads)*
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

**3. Install Chocolatey** *(skip if already installed)*
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```
Close and reopen PowerShell as Admin, then verify:
```powershell
choco --version
```

**4. Install Git and Python**
```powershell
choco install git -y
choco install python311 -y
```
Close and reopen PowerShell as Admin after each install, then verify:
```powershell
git --version
python --version
```

**5. Allow PowerShell scripts to run**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```

**6. Create project folder**
```powershell
New-Item -ItemType Directory -Force -Path C:\github_loc_audit
cd C:\github_loc_audit
# copy main.py into this folder
```

**7. Create and activate virtual environment**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```
You should see `(.venv)` at the start of your prompt.

**8. Install dependencies**
```powershell
pip install aiohttp tqdm
```

**9. Set environment variables** *(permanent — survives reboots)*
```powershell
[System.Environment]::SetEnvironmentVariable("GITHUB_ORG",   "your-org-name",           "Machine")
[System.Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "ghp_xxxxxxxxxxxxxxxxxxxx", "Machine")

# Refresh in current session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
```

---

## 🔑 Create a GitHub Personal Access Token

1. Go to: https://github.com/settings/tokens
2. Click **"Generate new token (classic)"**
3. Name it: `loc-audit`
4. Set expiration: **90 days**
5. Check these scopes:
   - ✅ `repo` — access to private repositories
   - ✅ `read:org` — list organization repositories
6. Click **"Generate token"**
7. **Copy the token immediately** — you cannot view it again

---

## ▶️ Run the auditor

### macOS / Linux
```bash
cd github_loc_audit
source .venv/bin/activate
python main.py
```

### Windows
```powershell
cd C:\github_loc_audit
.venv\Scripts\Activate.ps1
python main.py
```

---

## ⚙️ Options

```bash
# Custom batch size (default: 5 repos per batch)
python main.py --batch 10

# Re-fetch branch list from GitHub (keeps sized + audit CSVs)
python main.py --refetch

# Re-measure branch sizes (keeps audit CSV)
python main.py --remeasure

# Full reset — start everything from scratch
python main.py --refetch --remeasure
```

---

## 📋 How it works

```
Phase 1 — Fetch
  GitHub API → all repos + all branches → branches.csv

Phase 2 — Measure
  Clone each repo (--depth=1)
  └── Checkout every branch into a worktree
      └── Measure real disk size
  Delete clone → pick largest branch per repo → branches_sized.csv

Phase 3 — Audit (batched)
  For each largest branch:
    Clone repo (--depth=1)
    └── Checkout branch into worktree
        └── Count code / comment / blank lines
    Delete clone → append results to loc_audit.csv
```

Each phase checks for its output file on startup — **if the file exists, that phase is skipped**. This means:
- If the script crashes at batch 4 of 10, re-running it resumes from batch 5
- You can run `--refetch` to refresh the branch list without re-measuring or re-auditing

---

## ✅ Output files

| File | Description |
|---|---|
| `branches.csv` | All branches found across the org |
| `branches_sized.csv` | All branches with real measured disk sizes |
| `loc_audit.csv` | Final LOC results — one row per repo |
| `loc_audit_summary.txt` | Grand total summary |

### `loc_audit.csv` columns

| Column | Description |
|---|---|
| `organization` | GitHub org name |
| `repository` | Repository name |
| `branch` | Largest branch that was audited |
| `code_loc` | Non-blank, non-comment lines of code |
| `comment_lines` | Comment lines |
| `blank_lines` | Blank lines |
| `size_bytes` | Branch size in bytes (excluding skipped dirs) |
| `size_kb` | Branch size in KB |
| `size_mb` | Branch size in MB |

### Console summary example
```
=================================================================
  Organization   : your-org-name
  Repos audited  : 42
  Code LOC       : 1,250,430
  Comment lines  :    85,210
  Blank lines    :   120,870
=================================================================
```

---

## ⚡ Every time you run *(after first setup)*

### macOS / Linux
```bash
source .venv/bin/activate
python main.py
```

### Windows
```powershell
.venv\Scripts\Activate.ps1
python main.py
```

---

## 🔍 What gets skipped

The auditor automatically excludes the following from LOC counts:

**Directories:** `node_modules`, `vendor`, `.git`, `__pycache__`, `.venv`, `dist`, `build`, `target`, `.gradle`, `.idea`, `coverage`, `Pods`, `.next`, and more.

**File types:** Images, videos, fonts, archives, compiled binaries, certificates, data files (`.parquet`, `.pkl`, `.sqlite`), lock files, and minified files (`.min.js`, `.min.css`).

**Binary files:** Any file where more than 1% of its content is null bytes is automatically detected and skipped, regardless of extension.

---

## 🛠 Troubleshooting

| Error | Fix |
|---|---|
| `SSL: CERTIFICATE_VERIFY_FAILED` | Already handled — SSL verification is disabled for corporate networks |
| `python not found` (Windows) | Re-check PATH — see Windows setup Step 4 |
| `pip not found` | Use `python -m pip install aiohttp tqdm` instead |
| `.venv cannot be loaded` (Windows) | Re-run `Set-ExecutionPolicy` step |
| `No repositories found` | Check token has `repo` + `read:org` scopes and `GITHUB_ORG` is spelled correctly |
| `0 code 0 comment 0 blank` | Branch may be empty or contain only skipped file types |
| `Rate limited` | Script handles this automatically — waits and retries up to 8 times |
| `Timeout errors` | Reduce `REPO_CONCURRENCY` in the script config (default: 3) |