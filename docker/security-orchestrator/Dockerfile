# Enhanced Security Orchestrator Dockerfile
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PATH="/opt/venv/bin:$PATH"

# Set labels
LABEL maintainer="Security Orchestrator Team"
LABEL version="1.0.0"
LABEL description="Enhanced AI Agent Orchestrator for Offensive/Defensive Security"

# Create non-root user
RUN groupadd -r orchestrator && \
    useradd -r -g orchestrator -d /opt/security-orchestrator -s /bin/bash orchestrator

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Python and development tools
    python3.9 \
    python3.9-dev \
    python3-pip \
    python3.9-venv \
    build-essential \
    git \
    curl \
    wget \
    unzip \
    # Security tools
    nmap \
    wireshark-common \
    tcpdump \
    netcat-openbsd \
    # Cryptography
    libssl-dev \
    libffi-dev \
    # System monitoring
    htop \
    iotop \
    # Network tools
    iproute2 \
    iptables \
    # Other utilities
    sudo \
    jq \
    yq \
    && rm -rf /var/lib/apt/lists/*

# Install BlackArch repository (optional but recommended)
RUN curl -O https://blackarch.org/strap.sh && \
    chmod +x strap.sh && \
    ./strap.sh && \
    apt-get update && \
    apt-get install -y \
    # BlackArch security tools
    blackarch-web \
    blackarch-exploitation \
    blackarch-recon \
    blackarch-password \
    blackarch-cracker \
    blackarch-social \
    blackarch-defensive \
    # Additional security tools
    metasploit-framework \
    sqlmap \
    nikto \
    dirb \
    gobuster \
    hydra \
    john \
    hashcat \
    aircrack-ng \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /opt/security-orchestrator

# Create virtual environment
RUN python3.9 -m venv /opt/venv

# Upgrade pip and install wheel
RUN pip install --upgrade pip setuptools wheel

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Install additional security Python packages
RUN pip install \
    # Security frameworks
    pycryptodome \
    paramiko \
    scapy \
    # Malware analysis
    pefile \
    yara-python \
    volatility3 \
    # Web security
    requests \
    aiohttp \
    beautifulsoup4 \
    selenium \
    # Password cracking
    passlib \
    hashcat-python \
    # Network analysis
    psutil \
    netifaces \
    # Database
    psycopg2-binary \
    redis \
    # Monitoring
    prometheus-client \
    # Configuration
    pyyaml \
    python-dotenv \
    # Async support
    asyncio \
    aioredis \
    # API
    fastapi \
    uvicorn \
    # Authentication
    python-jose \
    passlib \
    bcrypt \
    # Data processing
    pandas \
    numpy \
    # Machine learning (optional)
    scikit-learn \
    tensorflow \
    # Image processing (for steganography)
    pillow \
    # Document processing
    python-docx \
    # Email processing
    email-validator \
    # DNS
    dnspython \
    # Cryptocurrency (for blockchain analysis)
    web3 \
    # Cloud SDKs
    boto3 \
    google-cloud \
    azure-storage-blob

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY docker/entrypoint.sh ./entrypoint.sh

# Create necessary directories
RUN mkdir -p /var/log/security-orchestrator \
    && mkdir -p /var/lib/security-orchestrator \
    && mkdir -p /etc/security-orchestrator \
    && mkdir -p /opt/security-orchestrator/tools \
    && mkdir -p /opt/security-orchestrator/workspace \
    && mkdir -p /opt/security-orchestrator/reports \
    && mkdir -p /opt/security-orchestrator/evidence

# Install Metasploit Framework
RUN msfdb init && \
    msfconsole -x "exit"

# Install additional security tools
RUN git clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
    cd /opt/metasploit-framework && \
    gem install bundler && \
    bundle install

# Install custom security tools
RUN mkdir -p /opt/custom-tools && \
    cd /opt/custom-tools && \
    # Install custom reconnaissance tools
    git clone https://github.com/laramies/theHarvester.git && \
    cd theHarvester && pip install -r requirements.txt && \
    cd .. && \
    # Install custom exploitation tools
    git clone https://github.com/sqlmapproject/sqlmap.git && \
    cd sqlmap && pip install -r requirements.txt && \
    cd .. && \
    # Install custom OSINT tools
    git clone https://github.com/smicallef/spiderfoot.git && \
    cd spiderfoot && pip install -r requirements.txt && \
    cd ..

# Set up configuration files
RUN cp config/orchestrator.yaml /etc/security-orchestrator/ && \
    cp config/agents.yaml /etc/security-orchestrator/ && \
    cp config/tools.yaml /etc/security-orchestrator/

# Create wordlists directory and download common wordlists
RUN mkdir -p /opt/wordlists && \
    cd /opt/wordlists && \
    wget -q https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt && \
    wget -q https://github.com/danielmiessler/SecLists/raw/master/Passwords/xato-net-10-million-passwords-1000000.txt && \
    wget -q https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt

# Set up SSL certificates (self-signed for development)
RUN mkdir -p /etc/security-orchestrator/ssl && \
    openssl req -x509 -newkey rsa:4096 -keyout /etc/security-orchestrator/ssl/key.pem -out /etc/security-orchestrator/ssl/cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=security-orchestrator"

# Set permissions
RUN chown -R orchestrator:orchestrator /opt/security-orchestrator && \
    chown -R orchestrator:orchestrator /var/log/security-orchestrator && \
    chown -R orchestrator:orchestrator /var/lib/security-orchestrator && \
    chown -R orchestrator:orchestrator /etc/security-orchestrator && \
    chmod +x ./entrypoint.sh && \
    chmod +x /opt/metasploit-framework/msfconsole && \
    chmod +x /opt/custom-tools/theHarvester/theHarvester.py

# Switch to non-root user
USER orchestrator

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set entrypoint
ENTRYPOINT ["./entrypoint.sh"]

# Default command
CMD ["python", "main.py"]
