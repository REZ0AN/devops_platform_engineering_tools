# Harness CI - Local Docker Delegate Setup for Linux (Ubuntu/Debian AMD64)

## Prerequisites
- Ubuntu/Debian-based Linux distribution (AMD64 architecture)
- Docker installed and running
- Harness account with Account ID and Delegate Token

## Verify System Architecture
```bash
# Check your architecture (should show x86_64 for AMD64)
uname -m
```

## Ensure Docker is Running
```bash
# Check if Docker running
docker ps

```

## Install Docker Delegate

For Linux, you can use `--net=host` which allows the delegate to communicate with the runner on localhost directly.
```bash
docker run --cpus=1 --memory=2g \
  --restart=always -d \
  --net=host \
  -e DELEGATE_NAME=<delegate_name> \
  -e NEXT_GEN="true" \
  -e DELEGATE_TYPE="DOCKER" \
  -e ACCOUNT_ID=<your_account_id_here> \
  -e DELEGATE_TOKEN=<your_delegate_token_here> \
  -e LOG_STREAMING_SERVICE_URL=https://app.harness.io/log-service/ \
  -e DELEGATE_TAGS="local-runner,linux-amd64" \
  -e MANAGER_HOST_AND_PORT=https://app.harness.io/ \
  harness/delegate:24.02.82203
```

**Note**: With `--net=host`, the delegate can reach the runner at `localhost:3000`. If you prefer not to use host networking, you can use `-p 8080:8080` and add `-e RUNNER_URL=http://172.17.0.1:3000` (Docker bridge IP).

This will create an account level docker delegate on your local machine. You can verify this by going to **Account Settings → Delegates**. You will see `<delegate_name>` listed there.

## Verify Delegate is Running
```bash
# Check if delegate container is running
docker ps

# View delegate logs
docker logs $(docker ps | grep delegate | awk '{print $1}')

# Or if you need sudo:
sudo docker logs $(sudo docker ps | grep delegate | awk '{print $1}')
```

## Install Harness Docker Runner
```bash
# Download runner for Linux AMD64
curl -LO https://github.com/harness/harness-docker-runner/releases/latest/download/harness-docker-runner-linux-amd64

# Make executable
chmod +x harness-docker-runner-linux-amd64

# Start runner in background
nohup ./harness-docker-runner-linux-amd64 server >runner-log.txt 2>&1 &
```

## Verify the Runner is Running
```bash
# Check health endpoint
curl http://localhost:3000/healthz

# Expected output:
# {
#   "version": "v0.1.21",
#   "docker_installed": true,
#   "git_installed": true,
#   "lite_engine_log": "no log file",
#   "ok": true
# }
```

## Verify End-to-End Connectivity
```bash
# Check runner process
ps aux | grep harness-docker-runner | grep -v grep

# Check delegate can reach runner
docker exec $(docker ps -q --filter ancestor=harness/delegate:24.02.82203) curl -s http://localhost:3000/healthz
```