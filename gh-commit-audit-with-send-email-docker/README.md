# GitHub Commit Audit [With Email and Dockerfile]

This repository generates GitHub commit audit CSVs per team and can optionally email them. It includes two main scripts: [audit_gen.sh](audit_gen.sh) (entrypoint) and [send_email.sh](send_email.sh) (email dispatcher). The repository also contains a Harness pipeline definition at `.harness/harness-pipeline.yaml` for CI.

## Files of interest
- [audit_gen.sh](audit_gen.sh): orchestrates fetching data (`get_data.py`), running `monthly_audit.py` per team, and optionally sends email reports.
- [send_email.sh](send_email.sh): sends generated CSVs to recipients listed in `email_recipients.txt` using the system `mail` tool and `msmtp` configured via `msmtprc`.
- [Dockerfile](Dockerfile): builds a container image that runs `audit_gen.sh` as the entrypoint.
- [.env.example](.env.example): example environment variables [see below](#envexample--variables-explained).
- [.harness/harness-pipeline.yaml](.harness/harness-pipeline.yaml): pipeline configuration used by Harness (CI/CD). Locally you can run the same steps manually (see "Local / Docker" section).

## .env.example — variables explained
Populate a `.env` file (copy from `.env.example`) before running locally or when passing `--env-file` to Docker. Key variables:

- `ORG_NAME`: GitHub organization to target.
- `TEAM_ID`: Github team from which you want to get the users from.
- `MONTH_START` / `MONTH_END`: start/end months for audits in `YYYY-MM` format.
- `IS_PERIOD`: `0` = use month range, `1` = use `PERIOD` (last N months from `MONTH_START`).
- `PERIOD`: number of months when `IS_PERIOD=1`.
- `GH_PAT`: GitHub Personal Access Token with repo/team read access.
- `APPLICATION_NAME`: application name used in reports.
- `SEND_EMAIL`: `true` or `false` — whether to trigger email sending after generation.
- `EMAIL_RECIPIENTS_FILE`: path to recipients list (default: `./email_recipients.txt`).
- `EMAIL_SUBJECT`: email subject prefix used by `send_email.sh`.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`: SMTP server details for sending email via `msmtp`.
- `SMTP_FROM`: envelope From address used by `msmtp`.
- `SMTP_SOURCE_NAME`: optional display/source name inserted into `msmtprc`.

Make sure `SMTP_USER` and `SMTP_PASSWORD` are set — `audit_gen.sh` will fail early if they are missing.

Sensitive values (like `GH_PAT` and SMTP credentials) should not be committed to VCS.

## msmtprc
The repository provides `msmtprc` which contains placeholders (e.g. `MAIL_HOST`, `MAIL_USER`, `MAIL_PASSWORD`, `SOURCE_NAME`). At runtime `audit_gen.sh` will replace those using `sed` and then test `msmtp` by sending a small test message. Ensure the file permissions are secure (recommended `chmod 600 msmtprc`).

## Harness pipeline (overview & local simulation)
.harness/harness-pipeline.yaml defines the CI/CD workflow used with Harness. It typically performs the same steps you can run locally: install dependencies, build the Docker image, and run tests or the audit container.

To simulate the pipeline locally, run the same commands the pipeline would run (build image, then run container). The Docker instructions below mirror what a Harness CI job would perform.

## Build and run with Docker (recommended)
Prefer mounting `msmtprc` and passing the environment at runtime instead of baking secrets into the image.

0. Create `./email_recipients.txt` and add one recipient email per line (ensure a newline after the last address).

1. Build the image:

```bash
docker build -t gh-commit-audit:latest .
```

2. Create (or copy) `.env` from `.env.example` and ensure `msmtprc` is configured locally and chmod'ed:

```bash
cp .env.example .env
chmod 600 msmtprc
```

3. Run the container (recommended runtime flags):

```bash
docker run --rm \
  --env-file .env \
  gh-commit-audit:latest
```

Notes on mounts and env:
- `--env-file .env` supplies variables to the container at runtime.

## Troubleshooting
- If `audit_gen.sh` exits with an SMTP error, check `SMTP_USER`, `SMTP_PASSWORD`, and that `msmtprc` placeholders are correctly replaced.
- If `repos.txt` or `team_users.txt` are missing/empty, inspect `get_data.py` run output — network or token (`GH_PAT`) issues are common causes.
- To debug inside the container, run an interactive shell:

```bash
docker run --rm -it --env-file .env -v "$(pwd)":/app gh-commit-audit:latest /bin/bash
```

## Security notes
- Do NOT commit `.env` with secrets to source control.
- Use CI/CD secret stores (Harness secrets, GitHub Actions secrets, etc.) for `GH_PAT` and SMTP credentials in pipelines.


