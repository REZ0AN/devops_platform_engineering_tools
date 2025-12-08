FROM python:3.10.17-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY get-data.py /app/
COPY monthly-audit.py /app/
COPY audit-gen.sh /app
COPY requirements.txt /app/
COPY .env /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt 

# Make the shell script executable
RUN chmod +x /app/audit-gen.sh

# Create data and output directories
RUN mkdir -p /audits /logs/error

# Set the entrypoint to the bash script
ENTRYPOINT ["/app/audit-gen.sh"]