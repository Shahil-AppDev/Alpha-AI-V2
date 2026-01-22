# OSINT Tools Container
# Specialized container for intelligence gathering tools

FROM archlinux:latest

# Install BlackArch repository
RUN wget -qO- https://blackarch.org/strap.sh | bash

# Install OSINT tools
RUN pacman -Syu --noconfirm --needed \
    theharvester \
    recon-ng \
    sherlock \
    maltego \
    spiderfoot \
    recon-cli \
    dnsenum \
    dnsrecon \
    fierce \
    sublist3r \
    amass \
    subfinder \
    assetfinder \
    subjack \
    subzy \
    dnsdumpster \
    whois \
    dig \
    nslookup \
    host \
    python \
    python-pip \
    git \
    curl \
    wget \
    jq

# Install Python OSINT libraries
RUN pip install --no-cache-dir \
    aiohttp \
    requests \
    beautifulsoup4 \
    lxml \
    python-whois \
    dnspython \
    shodan \
    passivetotal \
    vt-py \
    ipinfo \
    requests-html \
    selenium \
    webdriver-manager

# Create directories
RUN mkdir -p /data /config /output /wordlists

# Download wordlists
RUN wget -O /wordlists/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt && \
    wget -O /wordlists/names.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt && \
    wget -O /wordlists/companies.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-companies.txt

# Create non-root user
RUN useradd -m -u 1000 osint
RUN chown -R osint:osint /data /config /output /wordlists

# Set working directory
WORKDIR /data

# Switch to non-root user
USER osint

# Set environment variables
ENV PYTHONPATH=/data
ENV OSINT_CONFIG=/config
ENV OSINT_OUTPUT=/output

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD theHarvester -h || exit 1

# Default command
CMD ["/bin/bash"]
