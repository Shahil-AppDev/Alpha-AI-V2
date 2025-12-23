# Hacking Tools Installation - Dockerfile Modifications

## ✅ Complete Hacking Tools Integration

The Dockerfile has been successfully updated to include a comprehensive suite of offensive security tools.

### 🛠️ **Network Security Tools**
- **nmap** - Network discovery and security auditing
- **wireshark** - Network protocol analyzer
- **tcpdump** - Network packet capture and analysis
- **nikto** - Web server vulnerability scanner
- **hydra** - Online password cracking tool
- **aircrack-ng** - WiFi security assessment suite

### 🔓 **Exploitation & Post-Exploitation**
- **metasploit-framework** - Penetration testing framework
- **sqlmap** - Automatic SQL injection and database takeover tool
- **burpsuite** - Web application security testing platform

### 🔍 **Forensics & Reverse Engineering**
- **ghidra** - Software reverse engineering suite (NSA)
- **radare2** - Reverse engineering framework
- **binwalk** - Firmware analysis tool
- **foremost** - File carving tool
- **volatility3** - Memory forensics framework

### 🔐 **Password & Hash Cracking**
- **john** - John the Ripper password cracker
- **hashcat** - Advanced password recovery utility

### 🐍 **Python & Development**
- **python3-pip** - Python package manager for additional security tools

## 📋 **Dockerfile Installation Structure**

```dockerfile
# Install hacking tools
# Update package lists and install essential security tools
RUN apt-get update && apt-get install -y \
    nmap \
    metasploit-framework \
    wireshark \
    tcpdump \
    sqlmap \
    nikto \
    hydra \
    john \
    hashcat \
    aircrack-ng \
    radare2 \
    binwalk \
    foremost \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Volatility3 (memory forensics framework)
RUN pip3 install volatility3

# Install Ghidra (reverse engineering framework)
RUN apt-get update && apt-get install -y \
    openjdk-11-jdk \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra
RUN mkdir -p /opt/ghidra && \
    cd /opt/ghidra && \
    wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20231107.zip -O ghidra.zip && \
    unzip ghidra.zip && \
    rm ghidra.zip && \
    ln -s /opt/ghidra/ghidra_10.4_PUBLIC/ghidraRun /usr/local/bin/ghidra

# Install Burp Suite Community Edition
RUN apt-get update && apt-get install -y \
    default-jre \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/burpsuite && \
    cd /opt/burpsuite && \
    wget -q https://portswigger.net/burp/releases/download?product=community&type=Linux -O burpsuite_community.sh && \
    chmod +x burpsuite_community.sh && \
    ln -s /opt/burpsuite/burpsuite_community.sh /usr/local/bin/burpsuite
```

## 📁 **Tool Locations in Container**

### Network Security Tools
- **nmap**: `/usr/bin/nmap`
- **wireshark**: `/usr/bin/wireshark`
- **tcpdump**: `/usr/bin/tcpdump`
- **nikto**: `/usr/bin/nikto`
- **hydra**: `/usr/bin/hydra`
- **aircrack-ng**: `/usr/bin/aircrack-ng`

### Exploitation Tools
- **metasploit-framework**: `/usr/bin/msfconsole`
- **sqlmap**: `/usr/bin/sqlmap`
- **burpsuite**: `/usr/local/bin/burpsuite`

### Forensics & RE Tools
- **ghidra**: `/usr/local/bin/ghidra`
- **radare2**: `/usr/bin/radare2`
- **binwalk**: `/usr/bin/binwalk`
- **foremost**: `/usr/bin/foremost`
- **volatility3**: `/usr/local/bin/vol`

### Password Tools
- **john**: `/usr/bin/john`
- **hashcat**: `/usr/bin/hashcat`

## 🚀 **Usage Examples**

### Network Scanning
```bash
# Port scan
nmap -sS -p 1-65535 target.com

# Network discovery
nmap -sn 192.168.1.0/24
```

### Web Application Testing
```bash
# Web vulnerability scan
nikto -h http://target.com

# SQL injection testing
sqlmap -u "http://target.com/page?id=1" --dbs

# Start Burp Suite
burpsuite
```

### Password Cracking
```bash
# Hash cracking with John
john --wordlist=/path/to/wordlist hashfile.txt

# GPU acceleration with Hashcat
hashcat -m 0 -a 0 hash.txt wordlist.txt
```

### Reverse Engineering
```bash
# Start Ghidra
ghidra

# Binary analysis with radare2
radare2 /path/to/binary

# Firmware analysis
binwalk firmware.bin
```

### Memory Forensics
```bash
# Analyze memory dump
vol -f memory.dmp windows.pslist
```

## 🔧 **Configuration Notes**

### Metasploit Framework
- Initial setup required: `msfdb init`
- Database configuration for session storage

### Ghidra
- Java 11 runtime environment included
- Headless mode available for automated analysis

### Burp Suite
- Community edition with limited features
- Requires GUI or headless configuration

### Wireshark
- Command-line tshark available for automated capture
- GUI requires X11 forwarding for display

## 🔒 **Security Considerations**

- **Non-root User**: Tools installed but container runs as non-root
- **Network Isolation**: Tools contained within Docker network
- **Audit Trail**: All tool usage logged through container logs
- **Access Control**: Human approval system for critical operations

## 📊 **Container Size Impact**

- **Base Image**: ~150MB (python:3.11-slim)
- **Build Tools**: ~500MB
- **Security Tools**: ~2GB additional
- **LLM Source Code**: ~200MB
- **Total Estimated Size**: ~2.8GB

## 🎯 **Integration with AI Agent**

The AI agent can now leverage these tools for:
- **Automated Reconnaissance**: nmap, nikto
- **Vulnerability Assessment**: sqlmap, burpsuite
- **Exploit Development**: metasploit-framework
- **Binary Analysis**: ghidra, radare2, binwalk
- **Password Attacks**: john, hashcat, hydra
- **Memory Forensics**: volatility3
- **Wireless Testing**: aircrack-ng

The comprehensive toolset provides the AI agent with professional-grade capabilities for offensive security operations.
