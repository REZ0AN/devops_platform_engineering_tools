import asyncio
import csv
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import aiohttp
from tqdm.asyncio import tqdm as atqdm

# ─── CONFIG ───────────────────────────────────────────────────────────────────
ORG_NAME   = os.environ.get("GITHUB_ORG",   "your-org-name")
TOKEN      = os.environ.get("GITHUB_TOKEN", "your-token-here")
OUTPUT_CSV = "loc_audit.csv"
OUTPUT_TXT = "loc_audit_summary.txt"

# How many repos to clone/process in parallel.
# Keep ≤ 4 on Windows to avoid resource issues.
REPO_CONCURRENCY   = 4
# How many branches to process in parallel inside a single repo.
BRANCH_CONCURRENCY = 6
# ──────────────────────────────────────────────────────────────────────────────

BASE_URL = "https://api.github.com"
HEADERS  = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept":        "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# ─── SSL CONFIG (corporate network fix) ──────────────────────────────────────
# Option A: disable SSL verification entirely (quick fix)
# Option B: point to your corporate CA cert (proper fix)
#
# If you have the corporate CA cert (.pem or .crt), set the path below
# and switch SSL_MODE to "cert". Otherwise leave as "disabled".
#
SSL_MODE    = "disabled"              # "disabled" | "cert"
CA_CERT_PATH = r"C:\path\to\corp-ca.pem"  # only used when SSL_MODE = "cert"

def _make_ssl_context():
    if SSL_MODE == "cert":
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(CA_CERT_PATH)
        return ctx
    # "disabled" — skip verification entirely
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx

SSL_CONTEXT = _make_ssl_context()


# ─── CLOC HELPER ──────────────────────────────────────────────────────────────

def checkout_branch(repo_dir: Path, branch: str, worktree_dir: Path) -> bool:
    """Checkout a branch into a separate worktree directory."""
    try:
        # Remove worktree dir if it already exists
        if worktree_dir.exists():
            shutil.rmtree(worktree_dir, ignore_errors=True)

        subprocess.run(
            ["git", "worktree", "prune"],
            cwd=str(repo_dir), capture_output=True
        )
        subprocess.run(
            ["git", "worktree", "add", "--detach",
             str(worktree_dir), f"origin/{branch}"],
            cwd=str(repo_dir), check=True, capture_output=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"        ⚠ Cannot checkout '{branch}': {e}")
        return False


def run_cloc(repo_dir: Path, branch: str) -> dict:
    """
    Checkout branch into a worktree, run cloc on the directory directly.
    This avoids the --git flag which requires 'unzip' on Windows.
    Returns a dict with keys: code, comment, blank (all ints).
    """
    safe_branch  = re.sub(r'[^\w\-]', '_', branch)[:50]
    worktree_dir = repo_dir / f"wt_{safe_branch}"

    try:
        if not checkout_branch(repo_dir, branch, worktree_dir):
            return {"code": 0, "comment": 0, "blank": 0}

        cmd = [
            "cloc",
            "--json",
            "--quiet",
            str(worktree_dir),
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {"code": 0, "comment": 0, "blank": 0}

        data = json.loads(result.stdout)
        s = data.get("SUM", {})
        return {
            "code":    s.get("code",    0),
            "comment": s.get("comment", 0),
            "blank":   s.get("blank",   0),
        }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
        print(f"        ⚠ cloc error on branch '{branch}': {e}")
        return {"code": 0, "comment": 0, "blank": 0}
    finally:
        # Always clean up the worktree
        try:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree_dir)],
                cwd=str(repo_dir), capture_output=True
            )
        except Exception:
            pass
        shutil.rmtree(worktree_dir, ignore_errors=True)


# ─── GIT CLONE HELPER (shallow, SSL-aware) ────────────────────────────────────

def shallow_clone(auth_url: str, tmp_dir: str) -> None:
    """
    Shallow clone with --depth=1 and --no-single-branch.
    http.sslVerify=false mirrors the SSL_MODE setting for git.
    """
    ssl_flag = "false" if SSL_MODE == "disabled" else "true"
    cmd = [
        "git",
        "-c", f"http.sslVerify={ssl_flag}",
        "clone",
        "--depth=1",
        "--no-single-branch",
        "--quiet",
        auth_url,
        tmp_dir,
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)


# ─── ASYNC GITHUB API ─────────────────────────────────────────────────────────

async def _api_get(session: aiohttp.ClientSession, url: str,
                   params: dict | None = None) -> list | dict:
    backoff = 2
    for attempt in range(6):
        async with session.get(url, params=params, ssl=SSL_CONTEXT) as resp:
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
    repos = await paginate_async(session,
                                 f"{BASE_URL}/orgs/{org}/repos",
                                 {"type": "all"})
    print(f"   Found {len(repos)} repositories.\n")
    return repos


async def fetch_branches(session: aiohttp.ClientSession,
                         org: str, repo: str) -> list[str]:
    data = await paginate_async(
        session, f"{BASE_URL}/repos/{org}/{repo}/branches")
    return [b["name"] for b in data]


# ─── RESULT DATACLASS ─────────────────────────────────────────────────────────

@dataclass
class BranchResult:
    org:     str
    repo:    str
    branch:  str
    code:    int
    comment: int
    blank:   int


# ─── REPO PROCESSOR ──────────────────────────────────────────────────────────

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

    # Use Windows TEMP folder for clones
    tmp_base = os.environ.get("TEMP", "C:\\Temp")
    tmp_dir  = tempfile.mkdtemp(prefix=f"gh_{repo_name}_", dir=tmp_base)

    try:
        async with sem:
            try:
                # Shallow clone — fast and small on disk
                await loop.run_in_executor(
                    None, shallow_clone, auth_url, tmp_dir)

                branch_sem = asyncio.Semaphore(BRANCH_CONCURRENCY)

                async def _process_branch(branch: str) -> BranchResult:
                    async with branch_sem:
                        counts = await loop.run_in_executor(
                            None, run_cloc, Path(tmp_dir), branch)
                        print(
                            f"      🌿 {repo_name}/{branch}: "
                            f"{counts['code']:,} code  "
                            f"{counts['comment']:,} comment  "
                            f"{counts['blank']:,} blank"
                        )
                        return BranchResult(
                            ORG_NAME, repo_name, branch,
                            counts["code"], counts["comment"], counts["blank"]
                        )

                tasks   = [_process_branch(b) for b in branches]
                results = await asyncio.gather(*tasks)

            except Exception as e:
                print(f"      ⚠ Skipped '{repo_name}': {e}")
                results = [
                    BranchResult(ORG_NAME, repo_name, b, 0, 0, 0)
                    for b in branches
                ]
    finally:
        # Always delete the clone after the repo is fully processed
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"      🗑  Deleted clone: {tmp_dir}")

    return list(results)


# ─── OUTPUT WRITERS ───────────────────────────────────────────────────────────

def write_csv(rows: list[BranchResult], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["organization", "repository", "branch",
                    "code_loc", "comment_lines", "blank_lines"])
        for r in sorted(rows, key=lambda x: (x.repo, x.branch)):
            w.writerow([r.org, r.repo, r.branch,
                        r.code, r.comment, r.blank])
    print(f"\n✅ CSV written → {path}  ({len(rows)} rows)")


def write_summary(rows: list[BranchResult],
                  repos: list[dict], path: str) -> None:
    total_code    = sum(r.code    for r in rows)
    total_comment = sum(r.comment for r in rows)
    total_blank   = sum(r.blank   for r in rows)
    lines = [
        "=" * 65,
        f"  Organization   : {ORG_NAME}",
        f"  Repositories   : {len(repos)}",
        f"  Branches       : {len(all_rows := rows)}",
        f"  Code LOC       : {total_code:,}",
        f"  Comment lines  : {total_comment:,}",
        f"  Blank lines    : {total_blank:,}",
        "=" * 65,
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"✅ Summary written → {path}")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    # Windows ProactorEventLoop is default on Python 3.8+, fine to leave as-is
    connector = aiohttp.TCPConnector(limit=20, ssl=SSL_CONTEXT)
    timeout   = aiohttp.ClientTimeout(total=60)

    async with aiohttp.ClientSession(
        headers=HEADERS, connector=connector, timeout=timeout
    ) as session:

        repos = await fetch_repos(session, ORG_NAME)
        if not repos:
            print("No repositories found. Check ORG_NAME and GITHUB_TOKEN.")
            return

        sem      = asyncio.Semaphore(REPO_CONCURRENCY)
        all_rows: list[BranchResult] = []

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
    total_code    = sum(r.code    for r in all_rows)
    total_comment = sum(r.comment for r in all_rows)
    total_blank   = sum(r.blank   for r in all_rows)

    print(f"\n{'='*65}")
    print(f"  Organization   : {ORG_NAME}")
    print(f"  Repositories   : {len(repos)}")
    print(f"  Branches       : {len(all_rows)}")
    print(f"  Code LOC       : {total_code:,}")
    print(f"  Comment lines  : {total_comment:,}")
    print(f"  Blank lines    : {total_blank:,}")
    print(f"{'='*65}\n")

    write_summary(all_rows, repos, OUTPUT_TXT)
    write_csv(all_rows, OUTPUT_CSV)


if __name__ == "__main__":
    asyncio.run(main())