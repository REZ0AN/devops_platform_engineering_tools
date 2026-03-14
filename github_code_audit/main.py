import asyncio
import csv
import json
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
ORG_NAME   = os.environ.get("GITHUB_ORG",   "your-org-name")
TOKEN      = os.environ.get("GITHUB_TOKEN", "your-token-here")
OUTPUT_CSV = "loc_audit.csv"
OUTPUT_TXT = "loc_audit_summary.txt"

# How many repos to clone/process in parallel.
# Keep ≤ 5 to avoid hammering GitHub rate limits.
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
 

# ─── CLOC HELPER ──────────────────────────────────────────────────────────────

def run_cloc(repo_dir: Path, branch: str) -> dict:
    """
    Run cloc against a specific branch using --git inside the cloned repo.
    Returns a dict with keys: code, comment, blank (all ints).
    """
    cmd = [
        "cloc",
        "--json",
        "--quiet",
        "--git",
        f"origin/{branch}",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(repo_dir),
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
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return {"code": 0, "comment": 0, "blank": 0}


# ─── GIT CLONE HELPER (shallow) ───────────────────────────────────────────────

def shallow_clone(auth_url: str, tmp_dir: str, default_branch: str) -> None:
    """
    Shallow clone with --depth=1 and --no-single-branch so all remote
    branch refs are available for cloc --git to switch between.
    """
    cmd = [
        "git", "-c", "http.sslVerify=false",
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
    tmp_dir = tempfile.mkdtemp(prefix=f"gh_{repo_name}_")

    try:
        async with sem:
            try:
                # Shallow clone — fast, small on disk
                await loop.run_in_executor(
                    None, shallow_clone, auth_url, tmp_dir, default_branch)

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
        f"  Branches       : {len(rows)}",
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
    ssl_context = False
    connector = aiohttp.TCPConnector(limit=20,ssl=ssl_context)
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
