FROM python:3.10.17-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY get_data.py /app/
COPY monthly_audit.py /app/
COPY audit_gen.sh /app
COPY requirements.txt /app/
COPY .env /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt 

# Make the shell script executable
RUN chmod +x /app/audit_gen.sh

# Create data and output directories
RUN mkdir -p /audits /logs/error

# Set the entrypoint to the bash script
ENTRYPOINT ["/app/audit_gen.sh"]