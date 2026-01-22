# Network Security Tools Container
# Specialized container for network scanning and enumeration

FROM archlinux:latest

# Install BlackArch repository
RUN wget -qO- https://blackarch.org/strap.sh | bash

# Install network tools
RUN pacman -Syu --noconfirm --needed \
    nmap \
    masscan \
    nikto \
    unicornscan \
    hping3 \
    netdiscover \
    arp-scan \
    fping \
    nbtscan \
    smbclient \
    smbmap \
    enum4linux \
    rpcclient \
    showmount \
    nfs-common \
    snmpwalk \
    onesixtyone \
    snmp-check \
    hydra \
    medusa \
    patator \
    ncrack \
    sslscan \
    testssl.sh \
    sslyze \
    whatweb \
    wafw00f \
    gobuster \
    dirb \
    dirbuster \
    feroxbuster \
    ffuf \
    wfuzz \
    python \
    python-pip \
    git \
    curl \
    wget \
    jq \
    tcpdump \
    wireshark-cli \
    ngrep \
    dsniff \
    ettercap \
    bettercap

# Install Python network libraries
RUN pip install --no-cache-dir \
    python-nmap \
    scapy \
    paramiko \
    pycryptodome \
    requests \
    beautifulsoup4 \
    aiohttp \
    asyncio-redis

# Create directories
RUN mkdir -p /data /config /output /captures /scripts

# Install custom network scripts
COPY scripts/network/ /scripts/

# Create non-root user with network capabilities
RUN useradd -m -u 1000 netsec && \
    usermod -aG docker netsec

# Set working directory
WORKDIR /data

# Set permissions
RUN chown -R netsec:netsec /data /config /output /captures /scripts

# Switch to non-root user
USER netsec

# Set environment variables
ENV PYTHONPATH=/data
ENV NETSEC_CONFIG=/config
ENV NETSEC_OUTPUT=/output
ENV NETSEC_CAPTURES=/captures

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nmap --version || exit 1

# Default command
CMD ["/bin/bash"]
