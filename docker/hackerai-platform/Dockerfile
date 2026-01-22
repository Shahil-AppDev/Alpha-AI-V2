# HackerAI Platform - Universal Security Tool Container
# Multi-stage build for optimal size and security

# Base stage - Build environment
FROM archlinux:latest as builder

# Install build dependencies
RUN pacman -Syu --noconfirm --needed \
    base-devel \
    git \
    python \
    python-pip \
    docker \
    kubectl \
    wget \
    curl

# Install BlackArch repository
RUN wget -qO- https://blackarch.org/strap.sh | bash

# Install core security tools
RUN pacman -Syu --noconfirm --needed \
    # OSINT Tools
    theharvester \
    recon-ng \
    sherlock \
    maltego \
    # Network Scanning
    nmap \
    masscan \
    nikto \
    # Web Application
    sqlmap \
    burpsuite \
    zaproxy \
    # Password Cracking
    hashcat \
    john \
    hydra \
    # Exploitation
    metasploit \
    # Wireless
    aircrack-ng \
    bettercap \
    # Email & Social Engineering
    setoolkit \
    smtp-user-enum \
    # Forensics
    autopsy \
    volatility \
    # Post-exploitation
    empire \
    # Additional utilities
    wordlists \
    seclists \
    dnsutils \
    whois \
    netcat \
    tcpdump \
    wireshark-cli

# Python dependencies
RUN pip install --no-cache-dir \
    aiohttp \
    aiofiles \
    docker \
    kubernetes \
    pyyaml \
    requests \
    beautifulsoup4 \
    lxml \
    python-nmap \
    shodan \
    virustotal-api \
    passivetotal \
    python-whois \
    dnspython

# Production stage
FROM archlinux:latest

# Install runtime dependencies only
RUN pacman -Syu --noconfirm --needed \
    python \
    python-pip \
    nmap \
    whois \
    netcat \
    curl \
    jq \
    htop \
    strace

# Install Python runtime dependencies
COPY --from=builder /usr/lib/python3.11/site-packages /usr/lib/python3.11/site-packages
COPY --from=builder /usr/bin/python3.11 /usr/bin/python3.11

# Create non-root user for security
RUN useradd -m -u 1000 hackerai
RUN usermod -aG docker hackerai

# Create application directory
WORKDIR /opt/hackerai

# Copy application code
COPY src/ /opt/hackerai/src/
COPY requirements.txt /opt/hackerai/
COPY docker/entrypoint.sh /opt/hackerai/

# Set permissions
RUN chown -R hackerai:hackerai /opt/hackerai
RUN chmod +x /opt/hackerai/entrypoint.sh

# Switch to non-root user
USER hackerai

# Expose ports
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set environment variables
ENV PYTHONPATH=/opt/hackerai/src
ENV HACKERAI_CONFIG=/opt/hackerai/config
ENV HACKERAI_LOG_LEVEL=INFO
ENV HACKERAI_MAX_CONCURRENT_TOOLS=10

# Volume mounts
VOLUME ["/opt/hackerai/data", "/opt/hackerai/config", "/opt/hackerai/logs"]

# Entry point
ENTRYPOINT ["/opt/hackerai/entrypoint.sh"]

# Default command
CMD ["python", "-m", "src.main"]
