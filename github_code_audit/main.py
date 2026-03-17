import asyncio
import csv
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import aiohttp
from tqdm.asyncio import tqdm as atqdm

# ─── CONFIG ───────────────────────────────────────────────────────────────────
ORG_NAME        = os.environ.get("GITHUB_ORG",   "your-org-name")
TOKEN           = os.environ.get("GITHUB_TOKEN", "your-token-here")

BRANCHES_CSV    = "branches.csv"       # Phase 1 — all branches
SIZED_CSV       = "branches_sized.csv" # Phase 2 — branches with real sizes
AUDIT_CSV       = "loc_audit.csv"      # Phase 3 — LOC results
AUDIT_TXT       = "loc_audit_summary.txt"

BATCH_SIZE         = 5
REPO_CONCURRENCY   = 3
BRANCH_CONCURRENCY = 4
# ──────────────────────────────────────────────────────────────────────────────

BASE_URL = "https://api.github.com"
HEADERS  = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept":        "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# ─── SSL (corporate / Windows Server fix) ────────────────────────────────────
import ssl as _ssl
_ctx = _ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = _ssl.CERT_NONE
SSL_CONTEXT = _ctx

# ─── SKIP LISTS ───────────────────────────────────────────────────────────────
SKIP_DIRS = frozenset({
    ".git",
    "node_modules", "vendor", "bower_components", "packages", "Packages",
    "__pycache__", ".venv", "venv", "env", ".env", "site-packages", ".eggs",
    "dist", "build", "out", "output", "target", "bin", "obj",
    "release", "debug", "Release", "Debug",
    ".gradle", ".mvn", ".m2",
    ".idea", ".vscode", ".vs",
    "coverage", ".nyc_output", ".pytest_cache", "htmlcov", ".tox",
    "Pods", "DerivedData",
    ".next", ".nuxt", ".svelte-kit", "storybook-static", ".docusaurus",
})

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".tif", ".tiff", ".raw", ".psd", ".ai", ".eps", ".indd", ".sketch", ".fig",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".rar", ".7z", ".jar", ".war", ".ear", ".aar",
    ".class", ".pyc", ".pyo", ".pyd",
    ".o", ".a", ".so", ".dylib", ".lib",
    ".dll", ".exe", ".com", ".msi",
    ".apk", ".ipa", ".dex", ".wasm",
    ".ttf", ".woff", ".woff2", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg", ".aac",
    ".csv", ".tsv", ".dat", ".db", ".sqlite", ".sqlite3",
    ".rds", ".rda", ".rdata", ".sas7bdat", ".sav", ".dta",
    ".pkl", ".pickle", ".parquet", ".feather", ".arrow",
    ".npy", ".npz", ".h5", ".hdf5", ".mat",
    ".pem", ".crt", ".cer", ".cert", ".key", ".keystore", ".jks", ".p12",
    ".map", ".lock",
    ".mo", ".pbxproj", ".DS_Store",
    ".bin", ".img", ".iso", ".vmdk",
    ".blend", ".fbx", ".obj", ".stl", ".3ds",
})

SKIP_FILENAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "Cargo.lock",
    "poetry.lock", "pipfile.lock", "Pipfile.lock",
    ".DS_Store", "Thumbs.db", ".gitkeep",
})

# ─── BINARY SNIFF ─────────────────────────────────────────────────────────────
def _is_binary(filepath: Path) -> bool:
    try:
        chunk = filepath.read_bytes()[:8192]
        if not chunk:
            return False
        return chunk.count(b'\x00') / len(chunk) > 0.01
    except OSError:
        return True


# ─── LANGUAGE GROUPS ──────────────────────────────────────────────────────────
@dataclass
class LangGroup:
    name:         str
    extensions:   set
    single_line:  object = None
    block_start:  object = None
    block_end:    object = None
    inline_block: object = None

def _c(p, flags=0):
    return re.compile(p, flags) if p else None

LANGUAGE_GROUPS = [
    LangGroup("C-style",
        {".c",".h",".cpp",".cc",".cxx",".hpp",".cs",".java",
         ".js",".mjs",".jsx",".ts",".tsx",".kt",".go",".rs",
         ".swift",".dart",".php",".sol",".proto",".css",".scss",
         ".sass",".less",".vue",".svelte",".sql",".pgsql"},
        _c(r'^//'), _c(r'^/\*'), _c(r'\*/'), _c(r'^/\*.*?\*/\s*$')),
    LangGroup("Python",
        {".py", ".pyw"},
        _c(r'^#'), _c(r'^("""|\'\'\')'), _c(r'("""|\'\'\')'),
        _c(r'^("""|\'\'\').*?("""|\'\'\')$')),
    LangGroup("Hash",
        {".r",".R",".rb",".sh",".bash",".zsh",".fish",
         ".ps1",".psm1",".tf",".hcl",".yaml",".yml",
         ".toml",".awk",".graphql",".gql"},
        _c(r'^#')),
    LangGroup("SQL/Haskell",
        {".hs",".lhs",".elm"},
        _c(r'^--'), _c(r'^(/\*|\{-)'), _c(r'(\*/|-\})'),
        _c(r'^(/\*|\{-).*?(\*/|-\})\s*$')),
    LangGroup("Lua",
        {".lua"},
        _c(r'^--(?!\[\[)'), _c(r'^--\[\['), _c(r'\]\]'),
        _c(r'^--\[\[.*?\]\]\s*$')),
    LangGroup("HTML/XML",
        {".html",".htm",".xsd",".svg",".plist",
         ".csproj",".vbproj",".fsproj",".props",".targets"},
        None, _c(r'^<!--'), _c(r'-->'), _c(r'^<!--.*?-->\s*$')),
    LangGroup("SAS",
        {".sas"},
        _c(r'^\*'), _c(r'^/\*'), _c(r'\*/'), _c(r'^/\*.*?\*/\s*$')),
    LangGroup("VB",      {".vb", ".vbs"},  _c(r"^'")),
    LangGroup("PowerShell",
        {".ps1", ".psm1"},
        _c(r'^#(?!<)'), _c(r'^<#'), _c(r'#>'), _c(r'^<#.*?#>\s*$')),
    LangGroup("LaTeX",   {".tex",".sty",".bib"}, _c(r'^%')),
    LangGroup("Ruby",    {".rb"}, _c(r'^#'), _c(r'^=begin'), _c(r'^=end')),
    LangGroup("Erlang",  {".erl",".hrl"}, _c(r'^%')),
    LangGroup("OCaml",
        {".ml",".mli",".fs",".fsx"},
        _c(r'^//'), _c(r'^\(\*'), _c(r'\*\)'), _c(r'^\(\*.*?\*\)\s*$')),
    LangGroup("Batch",   {".bat",".cmd"}, _c(r'^(REM\b|::)', re.IGNORECASE)),
    LangGroup("Julia",
        {".jl"},
        _c(r'^#(?!=)'), _c(r'^#='), _c(r'=#'), _c(r'^#=.*?=#\s*$')),
    LangGroup("NoComments", {".json",".md",".markdown",".txt"}),
]

EXT_TO_GROUP = {}
for _grp in LANGUAGE_GROUPS:
    for _ext in _grp.extensions:
        EXT_TO_GROUP.setdefault(_ext, _grp)


# ─── LOC COUNTING ─────────────────────────────────────────────────────────────

def count_loc_in_file(filepath: Path) -> tuple:
    if filepath.name in SKIP_FILENAMES:
        return 0, 0, 0
    name_lower = filepath.name.lower()
    if any(name_lower.endswith(e) for e in (".min.js", ".min.css")):
        return 0, 0, 0
    ext   = filepath.suffix.lower()
    group = EXT_TO_GROUP.get(ext)
    if _is_binary(filepath):
        return 0, 0, 0
    try:
        lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return 0, 0, 0

    code_lines = comment_lines = blank_lines = 0
    in_block = False
    for raw in lines:
        line = raw.strip()
        if not line:
            blank_lines += 1
            continue
        if group is None:
            code_lines += 1
            continue
        if in_block:
            comment_lines += 1
            if group.block_end and group.block_end.search(line):
                in_block = False
            continue
        if group.inline_block and group.inline_block.match(line):
            comment_lines += 1
            continue
        if group.block_start and group.block_start.match(line):
            comment_lines += 1
            rest = line[group.block_start.match(line).end():]
            if not (group.block_end and group.block_end.search(rest)):
                in_block = True
            continue
        if group.single_line and group.single_line.match(line):
            comment_lines += 1
            continue
        code_lines += 1
    return code_lines, comment_lines, blank_lines


def count_loc_in_directory(directory: Path) -> tuple:
    total_code = total_comment = total_blank = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS and not d.endswith(".egg-info")
        ]
        for fname in files:
            fpath = Path(root) / fname
            ext   = fpath.suffix.lower()
            if not ext:
                if _is_binary(fpath):
                    continue
            elif ext in SKIP_EXTENSIONS:
                continue
            c, cm, b = count_loc_in_file(fpath)
            total_code    += c
            total_comment += cm
            total_blank   += b
    return total_code, total_comment, total_blank


# ─── GIT HELPERS ──────────────────────────────────────────────────────────────

def _git_env() -> dict:
    env = os.environ.copy()
    env["GIT_SSL_NO_VERIFY"] = "true"
    return env


def shallow_clone(auth_url: str, tmp_dir: str) -> None:
    subprocess.run(
        ["git", "clone", "--depth=1", "--no-single-branch",
         "--quiet", auth_url, tmp_dir],
        check=True, capture_output=True, text=True, env=_git_env(),
    )


def checkout_branch(repo_dir: Path, branch: str,
                    worktree_dir: Path) -> bool:
    env = _git_env()
    try:
        if worktree_dir.exists():
            shutil.rmtree(worktree_dir, ignore_errors=True)
        subprocess.run(["git", "worktree", "prune"],
                       cwd=str(repo_dir), capture_output=True, env=env)
        subprocess.run(
            ["git", "worktree", "add", "--detach",
             str(worktree_dir), f"origin/{branch}"],
            cwd=str(repo_dir), check=True,
            capture_output=True, text=True, env=env,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"        ⚠ Cannot checkout '{branch}': {e.stderr.strip()}")
        return False


def remove_worktree(repo_dir: Path, worktree_dir: Path) -> None:
    try:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree_dir)],
            cwd=str(repo_dir), capture_output=True, env=_git_env(),
        )
    except Exception:
        pass
    shutil.rmtree(worktree_dir, ignore_errors=True)


def get_dir_size(path: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            try:
                total += (Path(root) / fname).stat().st_size
            except OSError:
                pass
    return total


# ─── PHASE 2 HELPER: measure all branch sizes for one repo ───────────────────

def measure_repo_branches(entry_group: list[dict]) -> list[dict]:
    """
    Clone repo once, measure disk size of every branch via worktrees,
    return all entries enriched with real size_bytes.
    Repo clone is deleted after all branches are measured.
    """
    if not entry_group:
        return []

    first     = entry_group[0]
    repo      = first["repo"]
    clone_url = first["clone_url"]
    auth_url  = clone_url.replace("https://", f"https://oauth2:{TOKEN}@")

    clone_base = Path.cwd() / "clones"
    clone_base.mkdir(exist_ok=True)
    repo_dir   = clone_base / f"measure_{repo}"

    sized = []
    try:
        print(f"   📐 Cloning {repo} to measure branch sizes …")
        shallow_clone(auth_url, str(repo_dir))

        for entry in entry_group:
            branch = entry["branch"]
            safe   = re.sub(r'[^\w\-]', '_', branch)[:50]
            wt     = repo_dir / f"wt_{safe}"
            try:
                if checkout_branch(repo_dir, branch, wt):
                    size_bytes = get_dir_size(wt)
                    size_mb    = round(size_bytes / 1024 / 1024, 2)
                    print(f"      🌿 {branch}: {size_mb} MB")
                else:
                    size_bytes = 0
            except Exception as e:
                print(f"      ⚠ Could not measure {branch}: {e}")
                size_bytes = 0
            finally:
                remove_worktree(repo_dir, wt)

            sized.append({**entry, "size_bytes": size_bytes})

    except Exception as e:
        print(f"   ⚠ Could not clone {repo} for measuring: {e}")
        sized = [{**e, "size_bytes": 0} for e in entry_group]
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
        print(f"   🗑  Deleted measuring clone: {repo_dir}")

    return sized


# ─── ASYNC GITHUB API ─────────────────────────────────────────────────────────

async def _api_get(session: aiohttp.ClientSession, url: str,
                   params: dict | None = None) -> list | dict:
    backoff = 2
    for attempt in range(8):
        try:
            async with session.get(url, params=params,
                                   ssl=SSL_CONTEXT) as resp:
                if resp.status in (429, 403):
                    reset = int(resp.headers.get("X-RateLimit-Reset",
                                                 time.time() + 60))
                    wait  = max(reset - int(time.time()), 5) + 2
                    print(f"\n  ⏳ Rate-limited — waiting {wait}s …")
                    await asyncio.sleep(wait)
                    continue
                if resp.status in (500, 502, 503, 504):
                    await asyncio.sleep(backoff ** attempt)
                    continue
                resp.raise_for_status()
                return await resp.json()
        except asyncio.TimeoutError:
            wait = min(backoff ** attempt, 60)
            print(f"\n  ⏳ Timeout — retrying in {wait}s "
                  f"(attempt {attempt+1}/8)…")
            await asyncio.sleep(wait)
        except aiohttp.ClientConnectionError as e:
            wait = min(backoff ** attempt, 60)
            print(f"\n  ⚠ Connection error: {e} — retrying in {wait}s …")
            await asyncio.sleep(wait)
    print(f"\n  ✗ Gave up on {url} after 8 attempts")
    return []


async def paginate_async(session: aiohttp.ClientSession,
                         url: str, params: dict | None = None) -> list:
    params = dict(params or {})
    results, page = [], 1
    while True:
        params.update({"per_page": 100, "page": page})
        batch = await _api_get(session, url, params)
        if not batch:
            break
        results.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return results


# ─── PHASE 1: FETCH ALL BRANCHES → branches.csv ──────────────────────────────

async def fetch_all_branches(session: aiohttp.ClientSession,
                              org: str) -> list[dict]:
    print(f"\n📦 Fetching repository list for org: {org} …")
    repos = await paginate_async(session,
                                 f"{BASE_URL}/orgs/{org}/repos",
                                 {"type": "all"})
    if not repos:
        print("   No repositories found.")
        return []
    print(f"   Found {len(repos)} repositories. Fetching all branches …\n")

    sem = asyncio.Semaphore(10)

    async def _fetch(repo: dict) -> list[dict]:
        async with sem:
            repo_name    = repo["name"]
            clone_url    = repo["clone_url"]
            repo_size_kb = repo.get("size", 0)
            data = await paginate_async(
                session,
                f"{BASE_URL}/repos/{org}/{repo_name}/branches"
            )
            branches = [b["name"] for b in data]
            print(f"   ✔ {repo_name}  ({len(branches)} branch(es))")
            return [
                {
                    "org":          org,
                    "repo":         repo_name,
                    "branch":       b,
                    "clone_url":    clone_url,
                    "repo_size_kb": repo_size_kb,
                }
                for b in branches
            ]

    results = await asyncio.gather(*[_fetch(r) for r in repos])
    entries = [e for group in results for e in group]
    print(f"\n   Total: {len(entries)} branches across "
          f"{len(repos)} repositories.\n")
    return entries


def save_csv(entries: list[dict], path: str, fields: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(entries)
    print(f"✅ Saved → {path}  ({len(entries)} rows)")


def load_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ─── PHASE 2: MEASURE BRANCH SIZES → branches_sized.csv ─────────────────────

async def measure_all_branches(entries: list[dict]) -> list[dict]:
    """
    Group entries by repo, measure each branch's real disk size,
    save enriched list, then return only the LARGEST branch per repo.
    """
    # Group by repo
    repo_groups: dict[str, list[dict]] = {}
    for e in entries:
        repo_groups.setdefault(e["repo"], []).append(e)

    loop      = asyncio.get_running_loop()
    sem       = asyncio.Semaphore(REPO_CONCURRENCY)
    all_sized = []

    print(f"\n📐 Measuring branch sizes for "
          f"{len(repo_groups)} repos …\n")

    async def _measure(group: list[dict]) -> list[dict]:
        async with sem:
            return await loop.run_in_executor(
                None, measure_repo_branches, group)

    tasks   = [_measure(g) for g in repo_groups.values()]
    results = await atqdm.gather(*tasks, desc="Measuring")
    for r in results:
        all_sized.extend(r)

    # Save full sized list
    save_csv(all_sized, SIZED_CSV,
             ["org", "repo", "branch", "clone_url",
              "repo_size_kb", "size_bytes"])

    # Pick largest branch per repo
    largest: dict[str, dict] = {}
    for e in all_sized:
        repo       = e["repo"]
        size_bytes = int(e.get("size_bytes", 0))
        if repo not in largest or size_bytes > int(
                largest[repo].get("size_bytes", 0)):
            largest[repo] = e

    winners = sorted(largest.values(),
                     key=lambda x: int(x.get("size_bytes", 0)),
                     reverse=True)

    print(f"\n🏆 Largest branch per repo (sorted biggest first):")
    for w in winners:
        mb = round(int(w.get("size_bytes", 0)) / 1024 / 1024, 2)
        print(f"   {mb:>8} MB  →  {w['repo']}  "
              f"(branch: {w['branch']})")

    return winners


# ─── PHASE 3: AUDIT LARGEST BRANCHES ─────────────────────────────────────────

@dataclass
class AuditResult:
    org:        str
    repo:       str
    branch:     str
    code:       int
    comment:    int
    blank:      int
    size_bytes: int

    @property
    def size_kb(self) -> float:
        return round(self.size_bytes / 1024, 2)

    @property
    def size_mb(self) -> float:
        return round(self.size_bytes / 1024 / 1024, 2)


def audit_branch_entry(entry: dict) -> AuditResult:
    org       = entry["org"]
    repo      = entry["repo"]
    branch    = entry["branch"]
    clone_url = entry["clone_url"]
    auth_url  = clone_url.replace("https://",
                                  f"https://oauth2:{TOKEN}@")

    clone_base  = Path.cwd() / "clones"
    clone_base.mkdir(exist_ok=True)
    safe_branch = re.sub(r'[^\w\-]', '_', branch)[:40]
    tmp_dir     = clone_base / f"{repo}_{safe_branch}"
    tmp_dir.mkdir(exist_ok=True)

    try:
        shallow_clone(auth_url, str(tmp_dir))
        safe   = re.sub(r'[^\w\-]', '_', branch)[:50]
        wt     = tmp_dir / f"wt_{safe}"
        if not checkout_branch(tmp_dir, branch, wt):
            return AuditResult(org, repo, branch, 0, 0, 0, 0)
        try:
            size_bytes          = get_dir_size(wt)
            code, comment, blank = count_loc_in_directory(wt)
            return AuditResult(org, repo, branch,
                               code, comment, blank, size_bytes)
        finally:
            remove_worktree(tmp_dir, wt)
    except Exception as e:
        print(f"      ⚠ Failed {repo}/{branch}: {e}")
        return AuditResult(org, repo, branch, 0, 0, 0, 0)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"      🗑  Deleted clone: {tmp_dir}")


def write_audit_csv(rows: list[AuditResult], path: str) -> None:
    file_exists = Path(path).exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not file_exists:
            w.writerow(["organization", "repository", "branch",
                        "code_loc", "comment_lines", "blank_lines",
                        "size_bytes", "size_kb", "size_mb"])
        for r in rows:
            w.writerow([r.org, r.repo, r.branch,
                        r.code, r.comment, r.blank,
                        r.size_bytes, r.size_kb, r.size_mb])
    print(f"\n✅ Results appended → {path}  (+{len(rows)} rows)")


def write_summary(rows: list[AuditResult], path: str) -> None:
    total_code    = sum(r.code    for r in rows)
    total_comment = sum(r.comment for r in rows)
    total_blank   = sum(r.blank   for r in rows)
    lines = [
        "=" * 65,
        f"  Organization   : {ORG_NAME}",
        f"  Repos audited  : {len(rows)}",
        f"  Code LOC       : {total_code:,}",
        f"  Comment lines  : {total_comment:,}",
        f"  Blank lines    : {total_blank:,}",
        "=" * 65,
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"✅ Summary written → {path}")


async def audit_batch(entries: list[dict],
                      batch_size: int) -> list[AuditResult]:
    loop    = asyncio.get_running_loop()
    sem     = asyncio.Semaphore(REPO_CONCURRENCY)
    batches = [entries[i:i+batch_size]
               for i in range(0, len(entries), batch_size)]

    print(f"\n🔍 Auditing {len(entries)} repos in "
          f"{len(batches)} batch(es) of up to {batch_size} …\n")

    all_results = []
    for batch_num, batch in enumerate(batches, 1):
        print(f"  ─── Batch {batch_num}/{len(batches)} "
              f"({len(batch)} repos) ───")

        async def _run(e: dict) -> AuditResult:
            async with sem:
                result = await loop.run_in_executor(
                    None, audit_branch_entry, e)
                print(
                    f"      🌿 {result.repo}/{result.branch}: "
                    f"{result.code:,} code  "
                    f"{result.comment:,} comment  "
                    f"{result.blank:,} blank  "
                    f"({result.size_mb} MB)"
                )
                return result

        results = await atqdm.gather(
            *[_run(e) for e in batch], desc=f"  Batch {batch_num}")

        write_audit_csv(results, AUDIT_CSV)
        all_results.extend(results)

        if batch_num < len(batches):
            await asyncio.sleep(2)

    return all_results


# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main(batch_size: int) -> None:
    connector = aiohttp.TCPConnector(limit=10, limit_per_host=10)
    timeout   = aiohttp.ClientTimeout(total=120, connect=30, sock_read=60)

    async with aiohttp.ClientSession(
        headers=HEADERS, connector=connector, timeout=timeout
    ) as session:

        # ── PHASE 1: fetch all branches ───────────────────────────────────────
        if Path(BRANCHES_CSV).exists():
            print(f"📋 Found {BRANCHES_CSV} — skipping fetch phase.")
            print(f"   Delete it to re-fetch from GitHub.\n")
            entries = load_csv(BRANCHES_CSV)
            print(f"   Loaded {len(entries)} branches.\n")
        else:
            entries = await fetch_all_branches(session, ORG_NAME)
            if not entries:
                return
            save_csv(entries, BRANCHES_CSV,
                     ["org", "repo", "branch", "clone_url", "repo_size_kb"])

    # ── PHASE 2: measure branch sizes ─────────────────────────────────────────
    if Path(SIZED_CSV).exists():
        print(f"📋 Found {SIZED_CSV} — skipping measure phase.")
        print(f"   Delete it to re-measure.\n")
        sized = load_csv(SIZED_CSV)
        # Pick largest branch per repo from existing sized CSV
        largest: dict[str, dict] = {}
        for e in sized:
            repo       = e["repo"]
            size_bytes = int(e.get("size_bytes", 0))
            if repo not in largest or size_bytes > int(
                    largest[repo].get("size_bytes", 0)):
                largest[repo] = e
        winners = sorted(largest.values(),
                         key=lambda x: int(x.get("size_bytes", 0)),
                         reverse=True)
        print(f"   Picked {len(winners)} largest branches.\n")
    else:
        winners = await measure_all_branches(entries)

    # ── PHASE 3: audit largest branches ───────────────────────────────────────
    audited = set()
    if Path(AUDIT_CSV).exists():
        with open(AUDIT_CSV, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                audited.add((row["repository"], row["branch"]))
        if audited:
            print(f"⏭  Skipping {len(audited)} already-audited repos.\n")

    pending = [
        e for e in winners
        if (e["repo"], e["branch"]) not in audited
    ]

    if not pending:
        print("✅ All repos already audited. Nothing to do.")
        return

    print(f"📊 {len(pending)} repos to audit "
          f"({len(audited)} already done).\n")

    results = await audit_batch(pending, batch_size)

    # Final summary
    all_rows = results
    if audited:
        with open(AUDIT_CSV, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                all_rows.append(AuditResult(
                    row["organization"], row["repository"], row["branch"],
                    int(row["code_loc"]), int(row["comment_lines"]),
                    int(row["blank_lines"]), int(row["size_bytes"])
                ))

    print(f"\n{'='*65}")
    print(f"  Organization   : {ORG_NAME}")
    print(f"  Repos audited  : {len(all_rows)}")
    print(f"  Code LOC       : {sum(r.code    for r in all_rows):,}")
    print(f"  Comment lines  : {sum(r.comment for r in all_rows):,}")
    print(f"  Blank lines    : {sum(r.blank   for r in all_rows):,}")
    print(f"{'='*65}\n")
    write_summary(all_rows, AUDIT_TXT)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="GitHub LOC auditor — 3 phases: fetch → measure → audit"
    )
    parser.add_argument(
        "--batch", type=int, default=BATCH_SIZE,
        help=f"Repos per audit batch (default: {BATCH_SIZE})"
    )
    parser.add_argument(
        "--refetch", action="store_true",
        help="Re-fetch branch list from GitHub"
    )
    parser.add_argument(
        "--remeasure", action="store_true",
        help="Re-measure branch sizes even if branches_sized.csv exists"
    )
    args = parser.parse_args()

    if args.refetch:
        for f in [BRANCHES_CSV, SIZED_CSV]:
            if Path(f).exists():
                os.remove(f)
                print(f"🗑  Deleted {f}")

    if args.remeasure and Path(SIZED_CSV).exists():
        os.remove(SIZED_CSV)
        print(f"🗑  Deleted {SIZED_CSV}")

    asyncio.run(main(args.batch))