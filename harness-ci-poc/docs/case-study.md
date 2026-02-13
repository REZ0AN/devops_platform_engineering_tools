# Email Attachments Issue with Local Docker Runner - Resolution Documentation

## Problem Statement

**Issue**: Email attachments were not being sent when using the `plugins/email` plugin on a local Docker runner, despite files existing in the repository.

**Error**: Files appeared to be present in logs but were not attached to emails.

---

## Root Cause Analysis

### Step 1: Initial Attempt - Using Email Plugin

We initially tried the standard Harness email plugin approach:

```yaml
- step:
    type: Plugin
    image: plugins/email
    settings:
      attachment: /harness/recipients.txt,/harness/README.md
```

**Result**: Email sent successfully but **no attachments included**.

---

### Step 2: Investigation - File Path Testing

We added debug steps to verify file locations:

```yaml
- step:
    type: Run
    command: |-
      echo "=== Checking files ==="
      ls -lh /harness/recipients.txt
      ls -lh /harness/README.md
```

**Finding**: Files existed and were accessible in Run steps.

---

### Step 3: Tried Different File Paths

We attempted multiple path configurations:

```yaml
# Attempt 1: Absolute path
attachment: /harness/recipients.txt,/harness/README.md

# Attempt 2: Relative path  
attachment: recipients.txt,README.md

# Attempt 3: Copied to /tmp
attachment: /tmp/attachments/recipients.txt,/tmp/attachments/README.md
```

**Result**: None of these approaches worked.

---

### Step 4: Root Cause Identified

**The Problem**: 

On a local Docker Runner, email attachments failed when using the `plugins/email` step because this step runs in an isolated Docker container, preventing the plugin from accessing files created in previous run steps. This issue arises because the local runner's attempt to share volumes across host and container often fails due to Docker-in-Docker path mapping or permission issues on macOS. The other run steps runs directly on host machine.


---

## Solution: Python SMTP Script Approach

### Why This Works

Using a Python script in a **Run step** keeps everything in the host machine, allowing direct file access.

```
Single Run Step 
     |
  Python script runs here
     |
  Files accessible + Email sent
```


---

### Implementation

**Final Working Solution**:

```yaml
- step:
    type: Run
    name: Send Email with Python
    spec:
      shell: Sh
      command: |-
        # Install SMTP library
        pip3 install --quiet --no-cache-dir secure-smtplib
        
        # Create Python email script
        cat > /tmp/send_email.py << 'EOF'
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders
        import os
        
        # Get credentials from environment
        smtp_user = os.environ.get('SMTP_USER')
        smtp_pass = os.environ.get('SMTP_PASS')
        recipients = os.environ.get('RECIPIENTS').split(',')
        
        # Create email
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = 'Pipeline Report'
        msg.attach(MIMEText('Email body here', 'plain'))
        
        # Attach files directly
        for filename in ['recipients.txt', 'README.md']:
            with open(filename, 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={filename}')
                msg.attach(part)
        
        # Send email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        EOF
        
        # Set environment variables with secrets
        export SMTP_USER="<+secrets.getValue("SMTP_USER")>"
        export SMTP_PASS="<+secrets.getValue("SMTP_PASSWORD")>"
        export RECIPIENTS="<+pipeline.variables.email_recipients>"
        
        # Run the script
        python3 /tmp/send_email.py
```

---

## Key Learnings

### 1. Container Isolation on Local Runner
- Each step based on spec runs on separate Docker container
- No automatic file sharing between steps
- Plugin steps cannot access Run step files

### 2. Harness Cloud vs Local Runner

| Feature | Harness Cloud | Local Docker Runner |
|---------|---------------|---------------------|
| File sharing | Automatic | Manual (sharedPaths) |
| Plugin access | Works seamlessly | Isolated containers |
| Attachments | Plugin works | Requires workaround |

---

## Summary

**Problem**: Email plugin couldn't access files on local Docker runner due to container isolation.

**Solution**: Used Python SMTP script in a Run step, because it's runs on the host machine directly and can access the cloned files.

**Result**: Successfully sending emails with attachments from local Docker runner.
