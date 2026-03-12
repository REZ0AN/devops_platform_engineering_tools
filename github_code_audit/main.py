

import asyncio
import csv
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp
from git import Repo
from tqdm.asyncio import tqdm as atqdm

# ─── CONFIG ───────────────────────────────────────────────────────────────────
ORG_NAME    = os.environ.get("GITHUB_ORG",   "your-org-name")
TOKEN       = os.environ.get("GITHUB_TOKEN", "your-token-here")
OUTPUT_CSV  = "loc_audit.csv"
OUTPUT_TXT = "loc_audit_summary.txt"

# How many repos to clone/process in parallel.
# Keep ≤ 5 to avoid hammering GitHub's rate limits.
REPO_CONCURRENCY    = 4
# How many branches to process in parallel inside a single repo.
BRANCH_CONCURRENCY  = 6
# ──────────────────────────────────────────────────────────────────────────────

BASE_URL = "https://api.github.com"
HEADERS  = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept":        "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# ─── SKIP LISTS ───────────────────────────────────────────────────────────────
SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "__pycache__",
    ".idea", ".vscode", "dist", "build", "target", ".mvn",
    "bin", "obj", ".gradle", "coverage", ".nyc_output",
})

SKIP_EXTENSIONS = frozenset({
    # images
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".tif", ".tiff", ".raw", ".psd", ".ai", ".eps",
    # documents / office
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".xml",
    # archives
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".rar", ".7z",
    ".jar", ".war", ".ear", ".aar",
    # compiled / binary
    ".class", ".pyc", ".pyo", ".o", ".a", ".so",
    ".dll", ".exe", ".dylib", ".lib", ".apk", ".ipa", ".dex",
    # fonts / media
    ".ttf", ".woff", ".woff2", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    # data
    ".csv", ".tsv", ".dat", ".db", ".sqlite",
    ".rds", ".rda", ".rdata", ".sas7bdat", ".sav", ".dta",
    ".pkl", ".parquet", ".feather",
    # certs / keys
    ".pem", ".crt", ".cert", ".key", ".keystore",
    # lock / misc binary
    ".lock", ".map", ".mo", ".pbxproj", ".ds_store",
})

# ─── LANGUAGE GROUPS ─────────────────────────────────────────────────────────
@dataclass
class LangGroup:
    name:         str
    extensions:   set[str]
    single_line:  re.Pattern | None = None
    block_start:  re.Pattern | None = None
    block_end:    re.Pattern | None = None
    inline_block: re.Pattern | None = None

def _c(p: str | None, flags: int = 0) -> re.Pattern | None:
    return re.compile(p, flags) if p else None

LANGUAGE_GROUPS: list[LangGroup] = [
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
         ".toml",".awk",".jl",".graphql",".gql"},
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

    LangGroup("VB",
        {".vb", ".vbs"},
        _c(r"^'")),

    LangGroup("PowerShell",
        {".ps1", ".psm1"},
        _c(r'^#(?!<)'), _c(r'^<#'), _c(r'#>'), _c(r'^<#.*?#>\s*$')),

    LangGroup("LaTeX",
        {".tex",".sty",".bib"},
        _c(r'^%')),

    LangGroup("Ruby",
        {".rb"},
        _c(r'^#'), _c(r'^=begin'), _c(r'^=end')),

    LangGroup("Erlang",
        {".erl",".hrl"},
        _c(r'^%')),

    LangGroup("OCaml",
        {".ml",".mli",".fs",".fsx"},
        _c(r'^//'), _c(r'^\(\*'), _c(r'\*\)'), _c(r'^\(\*.*?\*\)\s*$')),

    LangGroup("Batch",
        {".bat",".cmd"},
        _c(r'^(REM\b|::)', re.IGNORECASE)),

    LangGroup("Julia",
        {".jl"},
        _c(r'^#(?!=)'), _c(r'^#='), _c(r'=#'), _c(r'^#=.*?=#\s*$')),

    LangGroup("NoComments",
        {".json",".md",".markdown",".txt"}),
]

EXT_TO_GROUP: dict[str, LangGroup] = {}
for _grp in LANGUAGE_GROUPS:
    for _ext in _grp.extensions:
        EXT_TO_GROUP.setdefault(_ext, _grp)   # first match wins


# ─── LOC COUNTING ─────────────────────────────────────────────────────────────

def count_loc_in_file(filepath: Path) -> int:
    ext   = filepath.suffix.lower()
    group = EXT_TO_GROUP.get(ext)

    try:
        lines = filepath.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return 0

    if group is None:
        # Unknown extension — count non-blank lines without comment stripping
        return sum(1 for l in lines if l.strip())

    loc = 0
    in_block = False

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        if in_block:
            if group.block_end and group.block_end.search(line):
                in_block = False
            continue

        if group.inline_block and group.inline_block.match(line):
            continue

        if group.block_start and group.block_start.match(line):
            rest = line[group.block_start.match(line).end():]
            if not (group.block_end and group.block_end.search(rest)):
                in_block = True
            continue

        if group.single_line and group.single_line.match(line):
            continue

        loc += 1

    return loc


def count_loc_in_directory(directory: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if not ext or ext in SKIP_EXTENSIONS:
                continue
            total += count_loc_in_file(Path(root) / fname)
    return total


# ─── ASYNC GITHUB API ─────────────────────────────────────────────────────────

async def _api_get(session: aiohttp.ClientSession, url: str,
                   params: dict | None = None) -> list | dict:
    """Single GET with rate-limit + retry handling."""
    backoff = 2
    for attempt in range(6):
        async with session.get(url, params=params) as resp:
            if resp.status in (429, 403):
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait  = max(reset - int(time.time()), 5) + 2
                print(f"\n  ⏳ Rate-limited — waiting {wait}s …")
                await asyncio.sleep(wait)
                continue
            if resp.status in (500, 502, 503, 504):
                await asyncio.sleep(backoff ** attempt)
                continue
            resp.raise_for_status()
            return await resp.json()
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


async def fetch_repos(session: aiohttp.ClientSession, org: str) -> list[dict]:
    print(f"📦 Fetching repositories for org: {org}")
    repos = await paginate_async(session, f"{BASE_URL}/orgs/{org}/repos",
                                 {"type": "all"})
    print(f"   Found {len(repos)} repositories.\n")
    return repos


async def fetch_branches(session: aiohttp.ClientSession,
                         org: str, repo: str) -> list[str]:
    data = await paginate_async(session,
                                f"{BASE_URL}/repos/{org}/{repo}/branches")
    return [b["name"] for b in data]


# ─── GIT HELPERS (run in thread pool) ────────────────────────────────────────

def _clone(auth_url: str, tmp_dir: str, default_branch: str) -> Repo:
    try:
        return Repo.clone_from(auth_url, tmp_dir,
                               branch=default_branch,
                               no_single_branch=True)
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        os.makedirs(tmp_dir, exist_ok=True)
        return Repo.clone_from(auth_url, tmp_dir, no_single_branch=True)


def _safe_branch_name(branch: str) -> str:
    return re.sub(r'[^\w\-]', '_', branch).strip("_")[:60]


def _count_branch_loc(cloned_repo: Repo, branch: str, work_dir: str) -> int:
    wt_path = os.path.join(work_dir, f"wt_{_safe_branch_name(branch)}")
    if os.path.exists(wt_path):
        shutil.rmtree(wt_path, ignore_errors=True)
    try:
        cloned_repo.git.worktree("prune")
    except Exception:
        pass
    try:
        cloned_repo.git.worktree("add", "--detach", wt_path, f"origin/{branch}")
    except Exception as e:
        print(f"        ⚠ Cannot checkout '{branch}': {e}")
        return 0
    try:
        return count_loc_in_directory(Path(wt_path))
    finally:
        try:
            cloned_repo.git.worktree("remove", "--force", wt_path)
        except Exception:
            pass
        shutil.rmtree(wt_path, ignore_errors=True)
        try:
            cloned_repo.git.worktree("prune")
        except Exception:
            pass


# ─── REPO PROCESSOR ──────────────────────────────────────────────────────────

@dataclass
class BranchResult:
    org:    str
    repo:   str
    branch: str
    loc:    int

async def process_repo(session: aiohttp.ClientSession,
                       repo_meta: dict,
                       repo_idx: int,
                       total_repos: int,
                       sem: asyncio.Semaphore) -> list[BranchResult]:
    repo_name      = repo_meta["name"]
    clone_url      = repo_meta["clone_url"]
    default_branch = repo_meta.get("default_branch", "main")
    auth_url       = clone_url.replace("https://",
                                       f"https://oauth2:{TOKEN}@")

    branches = await fetch_branches(session, ORG_NAME, repo_name)
    print(f"  [{repo_idx}/{total_repos}] {repo_name}  "
          f"({len(branches)} branch(es))")

    results: list[BranchResult] = []
    loop    = asyncio.get_running_loop()
    tmp_dir = tempfile.mkdtemp(prefix=f"gh_{repo_name}_")

    try:
        async with sem:
            try:
                cloned_repo = await loop.run_in_executor(
                    None, _clone, auth_url, tmp_dir, default_branch)

                branch_sem = asyncio.Semaphore(BRANCH_CONCURRENCY)

                async def _process_branch(branch: str) -> BranchResult:
                    async with branch_sem:
                        loc = await loop.run_in_executor(
                            None, _count_branch_loc,
                            cloned_repo, branch, tmp_dir)
                        print(f"      🌿 {repo_name}/{branch}: {loc:,} LOC")
                        return BranchResult(ORG_NAME, repo_name, branch, loc)

                tasks   = [_process_branch(b) for b in branches]
                results = await asyncio.gather(*tasks)

            except Exception as e:
                print(f"      ⚠ Skipped '{repo_name}': {e}")
                results = [BranchResult(ORG_NAME, repo_name, b, 0)
                           for b in branches]
    finally:
        # Always runs — even if semaphore acquire is interrupted
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"      🗑  Cleaned up clone: {tmp_dir}")

    return list(results)
                           
# ─── CSV WRITER ───────────────────────────────────────────────────────────────

def write_csv(rows: list[BranchResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["organization", "repository", "branch", "loc"])
        for r in sorted(rows, key=lambda x: (x.repo, x.branch)):
            w.writerow([r.org, r.repo, r.branch, r.loc])
    print(f"\n✅ CSV written → {path}  ({len(rows)} rows)")

def write_summary(rows: list[BranchResult], repos: list[dict], path: str) -> None:
    grand_total = sum(r.loc for r in rows)
    lines = [
        "=" * 65,
        f"  Organization  : {ORG_NAME}",
        f"  Repositories  : {len(repos)}",
        f"  Branches      : {len(rows)}",
        f"  GRAND TOTAL   : {grand_total:,} LOC  (all branches, comments stripped)",
        "=" * 65,
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"✅ Summary written → {path}")

# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    connector = aiohttp.TCPConnector(limit=20)
    timeout   = aiohttp.ClientTimeout(total=60)

    async with aiohttp.ClientSession(
        headers=HEADERS, connector=connector, timeout=timeout
    ) as session:

        repos = await fetch_repos(session, ORG_NAME)
        if not repos:
            print("No repositories found. Check your ORG_NAME and GITHUB_TOKEN.")
            return

        sem        = asyncio.Semaphore(REPO_CONCURRENCY)
        all_rows:  list[BranchResult] = []

        print(f"📊 Processing {len(repos)} repos "
              f"(concurrency: {REPO_CONCURRENCY} repos, "
              f"{BRANCH_CONCURRENCY} branches each)…\n")

        tasks = [
            process_repo(session, repo, idx, len(repos), sem)
            for idx, repo in enumerate(repos, 1)
        ]

        for coro in atqdm(asyncio.as_completed(tasks),
                          total=len(tasks), desc="Repos"):
            batch = await coro
            all_rows.extend(batch)

    # ── Summary ───────────────────────────────────────────────────────────────
    grand_total = sum(r.loc for r in all_rows)
    print(f"\n{'='*65}")
    print(f"  Organization  : {ORG_NAME}")
    print(f"  Repositories  : {len(repos)}")
    print(f"  Branches      : {len(all_rows)}")
    print(f"  GRAND TOTAL   : {grand_total:,} LOC  (all branches, comments stripped)")
    print(f"{'='*65}\n")
    write_summary(all_rows, repos, OUTPUT_TXT)
    write_csv(all_rows, OUTPUT_CSV)


if __name__ == "__main__":
    asyncio.run(main())
