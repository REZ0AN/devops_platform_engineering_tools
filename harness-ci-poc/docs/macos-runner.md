# Harness CI - Local Docker Delegate Setup for macOS (Apple Silicon)

This guide will help you set up a local Harness CI build infrastructure on macOS with Apple Silicon (M1/M2/M3 chips).

# Prerequisites

- macOS with Apple Silicon (M1/M2/M3)
- Docker Desktop installed and running
- Harness account credentials:
  - **Account ID** (found in Account Settings → Overview)
  - **Delegate Token** (create in Account Settings → Delegates → Tokens)

# Verify Docker is Running

```bash
# Check if Docker is running
docker ps

# If Docker is not running, start Docker Desktop
open -a Docker

# Wait for Docker to start, then verify
docker ps
```

# Install Docker Delegate

The delegate runs in a Linux container managed by Docker Desktop. Because Docker Desktop uses a VM on macOS, you need to explicitly set the `RUNNER_URL` to communicate with the runner on your Mac host.

## Replace the following placeholders
- `<delegate_name>` - A descriptive name for your delegate (e.g., `mac-m1-delegate`)
- `<your_account_id_here>` - Your Harness Account ID
- `<your_delegate_token_here>` - Your Delegate Token

```bash
docker run --cpus=1 --memory=2g \
  --restart=always -d \
  -p 8080:8080 \
  -e DELEGATE_NAME=<delegate_name> \
  -e NEXT_GEN="true" \
  -e DELEGATE_TYPE="DOCKER" \
  -e ACCOUNT_ID=<your_account_id_here> \
  -e DELEGATE_TOKEN=<your_delegate_token_here> \
  -e LOG_STREAMING_SERVICE_URL=https://app.harness.io/log-service/ \
  -e DELEGATE_TAGS="local-runner,darwin-arm64,macos-arm64" \
  -e MANAGER_HOST_AND_PORT=https://app.harness.io/ \
  -e RUNNER_URL=http://host.docker.internal:3000 \
  harness/delegate:24.02.82203
```

## Key Configuration
- `RUNNER_URL=http://host.docker.internal:3000` - Special hostname that allows the Linux container to reach your macOS host
- `DELEGATE_TAGS` - Multiple tags for flexibility in pipeline targeting
- `-p 8080:8080` - Exposes delegate port (required on macOS instead of `--net=host`)

## Where to find this delegate
After installation, verify in Harness UI: **Account Settings → Account Resources → Delegates**. You should see `<delegate_name>` listed with a **Connected** status (may take 1-2 minutes).

# Verify Delegate is Running

```bash
# Check if the delegate container is running
docker ps | grep delegate

# View delegate logs to ensure it's connecting properly
docker logs $(docker ps | grep delegate | awk '{print $1}')
```


# Install Harness Docker Runner

The runner is a lightweight service that executes your CI builds on your local machine.

```bash
# Download the runner binary for Apple Silicon
curl -LO https://github.com/harness/harness-docker-runner/releases/latest/download/harness-docker-runner-darwin-arm64

# Make the binary executable
chmod +x harness-docker-runner-darwin-arm64

# Start the runner as a background process
nohup ./harness-docker-runner-darwin-arm64 server >runner-log.txt 2>&1 &
```

# Verify Runner is Running

```bash
# Check the runner health endpoint
curl http://localhost:3000/healthz
```

**Expected output:**
```json
{
  "version": "v0.1.21",
  "docker_installed": true,
  "git_installed": true,
  "lite_engine_log": "no log file",
  "ok": true
}
```


# Verify End-to-End connectivity
```bash
docker exec $(docker ps -q --filter ancestor=harness/delegate:24.02.82203) \
  curl -v http://host.docker.internal:3000/healthz
```


