# Base image: Ubuntu 22.04 LTS for wide compatibility
FROM ubuntu:22.04

# Set non-interactive frontend to avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    openssl \
    curl \
    dnsutils \
    git \
    nikto \
    whatweb \
    # wafw00f is installed via pip
    # sqlmap is not in default repos, will be cloned from git
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

# Install sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# Set up the working directory
WORKDIR /app

# Copy application files
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Make the security script executable
RUN chmod +x ./security_test.sh

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["python3", "app.py"]

