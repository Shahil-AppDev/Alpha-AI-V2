# Password Cracking Tools Container
# GPU-enabled container for password recovery tools

FROM nvidia/cuda:12.1-devel-ubuntu22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    wget \
    curl \
    pkg-config \
    libssl-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libpcap-dev \
    libgmp-dev \
    libidn11-dev \
    zlib1g-dev \
    libffi-dev \
    libncursesw5-dev \
    libncurses5-dev \
    libssl-dev \
    libgmp-dev \
    python3 \
    python3-pip \
    python3-dev \
    nvidia-driver-535 \
    nvidia-cuda-toolkit \
    nvidia-cuda-dev \
    ocl-icd-opencl-dev \
    opencl-headers \
    clinfo \
    hashcat \
    john \
    hashcat-utils \
    john-the-ripper \
    crunch \
    maskprocessor \
    princeprocessor \
    wordlists \
    seclists \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir \
    aiohttp \
    asyncio-redis \
    requests \
    pyopencl \
    pycryptodome \
    hashcat-python

# Clone and install latest hashcat (if needed)
RUN cd /tmp && \
    git clone https://github.com/hashcat/hashcat.git && \
    cd hashcat && \
    make && \
    make install && \
    cd / && rm -rf /tmp/hashcat

# Clone and install latest John the Ripper
RUN cd /tmp && \
    git clone https://github.com/openwall/john.git && \
    cd john/src && \
    ./configure --enable-opencl --enable-cuda && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf /tmp/john

# Install additional password tools
RUN wget -O /usr/local/bin/hydra https://github.com/vanhauser-thc/thc-hydra/archive/refs/heads/master.tar.gz && \
    cd /tmp && \
    tar xzf master.tar.gz && \
    cd thc-hydra-master && \
    ./configure && \
    make && \
    make install && \
    cd / && rm -rf /tmp/thc-hydra-master

# Create directories
RUN mkdir -p /data /config /output /hashes /wordlists /rules /sessions

# Download essential wordlists
RUN wget -O /wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/raw/master/wordlists/rockyou.txt && \
    wget -O /wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt && \
    wget -O /wordlists/500-worst-passwords.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Worst-Pwds/500-worst-passwords.txt

# Download hashcat rules
RUN git clone https://github.com/HashCat/hashcat-rules.git /rules/hashcat && \
    git clone https://github.com/NSAKEY/nsa-rules.git /rules/nsa

# Create non-root user
RUN useradd -m -u 1000 password && \
    usermod -aG docker password

# Set working directory
WORKDIR /data

# Set permissions
RUN chown -R password:password /data /config /output /hashes /wordlists /rules /sessions

# Switch to non-root user
USER password

# Set environment variables
ENV PYTHONPATH=/data
ENV PASSWORD_CONFIG=/config
ENV PASSWORD_OUTPUT=/output
ENV PASSWORD_HASHES=/hashes
ENV PASSWORD_WORDLISTS=/wordlists
ENV PASSWORD_RULES=/rules
ENV CUDA_VISIBLE_DEVICES=0

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD hashcat --version || exit 1

# Default command
CMD ["/bin/bash"]
