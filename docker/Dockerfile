# AI-Driven Offensive Security Tool
# Dockerfile for the offensive security platform

# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install essential build tools
RUN apt-get update && apt-get install -y \
    git \
    wget \
    curl \
    build-essential \
    cmake \
    pkg-config \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create directories for LLMs and hacking tools
RUN mkdir -p /opt/llms /opt/hacking_tools

# Clone LLM source code repositories
# NOTE: These are source code clones only. Model weights would need to be downloaded separately
# and are typically not included in Docker images due to their large size and licensing restrictions.
# IMPORTANT: LLM weights should be managed separately using volume mounts.
# Mount local weights directory to /opt/llms/weights in the container to avoid including large model files in the image.

# Clone Mixtral 7B source code
RUN git clone https://github.com/mistralai/mistral-src.git /opt/llms/mixtral-7b

# Clone Llama 3B source code  
RUN git clone https://github.com/facebookresearch/llama.git /opt/llms/llama-3b

# Clone GPT-J source code
RUN git clone https://github.com/kingoflolz/mesh-transformer-jax.git /opt/llms/gpt-j

# Clone Vicuna source code
RUN git clone https://github.com/lm-sys/FastChat.git /opt/llms/vicuna

# Install hacking tools
# Update package lists and install essential security tools
RUN apt-get update && apt-get install -y \
    nmap \
    wireshark \
    tcpdump \
    hydra \
    john \
    hashcat \
    aircrack-ng \
    binwalk \
    foremost \
    python3-pip \
    curl \
    gpg \
    && rm -rf /var/lib/apt/lists/*

# Install tools that require alternative installation methods
# Install Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto

# Install SQLMap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install Volatility3 (memory forensics framework)
RUN pip3 install volatility3

# Install basic reverse engineering tools
RUN apt-get update && apt-get install -y \
    default-jdk \
    wget \
    unzip \
    file \
    hexedit \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY src/requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Install additional Python packages for LLM integration and security tools
# NOTE: Additional dependencies might be required based on specific LLM frameworks and tool integrations
# CPU-only installation for PyTorch to reduce image size and avoid GPU dependencies
RUN pip install --no-cache-dir \
    scapy \
    requests \
    beautifulsoup4 \
    python-dotenv \
    langchain \
    torch --index-url https://download.pytorch.org/whl/cpu \
    openai

# Copy application code to container
COPY src/ ./src/
COPY main.py .

# Set default command
CMD ["python3", "main.py"]
