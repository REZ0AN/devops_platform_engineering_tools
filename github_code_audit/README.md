# GitHub Organization LOC Auditor

Counts non‑blank, non‑comment **Lines of Code (LOC)** for every branch of every repository in a GitHub organization.  
Output is a CSV (`loc_audit.csv`) with one row per `(repo, branch)`.

---

## 🛠 Prerequisites

- Python 3.8+  
- [cloc](https://github.com/AlDanial/cloc)
- `git` installed and on your `PATH`  
- A [GitHub personal access token](https://github.com/settings/tokens) with at least `repo`/`public_repo` scope.

---

## 🔧 Setup

1. **Create & activate a virtual environment**  
   ```bash
   python -m venv .venv
   source .venv/bin/activate          # macOS / Linux
   # .venv\Scripts\activate           # Windows (PowerShell)
   ```

2. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```
3. **Install cloc**
- macOS:
```bash
brew install cloc
```
- Ubuntu/Debian:
```bash
sudo apt install cloc
```
- Windows:
```bash
winget install AlDanial.Cloc
```
- Verify it works:
```bash
cloc --version
```

4. **Set environment variables**

   ```bash
   export GITHUB_TOKEN="ghp_…"        # your personal access token
   export GITHUB_ORG="your-org-name"  # organization to audit
   ```

   (Windows PowerShell: `setx GITHUB_TOKEN "ghp_…"` etc.)

---

## ▶️ Run the auditor

```bash
python main.py
```

The script will:

1. fetch every repo in the org,
2. enumerate branches,
3. clone repos and count LOC per branch,
4. write results to `loc_audit.csv`.

---

## ✅ Output

- `loc_audit.csv` – columns: `organization,repository,branch,code_loc,comment_lines,blank_lines`
- Console Organization based summary with total Repository, Branch CLOC_LOC, Comment Lines, Blank Lines counts.

---
