#!/bin/bash
# Installation des outils de sécurité sur le serveur
# Alpha AI Platform - Qatar One

echo "🔧 Installation des outils de sécurité sur le serveur..."
echo ""

# Créer le répertoire tools
mkdir -p /var/www/qatar-one/tools
cd /var/www/qatar-one/tools

# Fonction pour cloner un outil
clone_tool() {
    local name=$1
    local url=$2
    
    if [ -d "$name" ]; then
        echo "⚠️  $name existe déjà, mise à jour..."
        cd "$name"
        git pull --quiet
        cd ..
    else
        echo "📦 Clonage de $name..."
        git clone --depth 1 --quiet "$url" 2>&1 | grep -v "Cloning into"
        if [ $? -eq 0 ]; then
            echo "✅ $name installé"
        else
            echo "❌ Échec de $name"
        fi
    fi
}

# Installation des outils
clone_tool "metasploit-framework" "https://github.com/rapid7/metasploit-framework.git"
clone_tool "sqlmap" "https://github.com/sqlmapproject/sqlmap.git"
clone_tool "PowerSploit" "https://github.com/PowerShellMafia/PowerSploit.git"
clone_tool "beef" "https://github.com/beefproject/beef.git"
clone_tool "nmap" "https://github.com/nmap/nmap.git"
clone_tool "nikto" "https://github.com/sullo/nikto.git"
clone_tool "recon-ng" "https://github.com/lanmaster53/recon-ng.git"
clone_tool "spiderfoot" "https://github.com/smicallef/spiderfoot.git"
clone_tool "theHarvester" "https://github.com/laramies/theHarvester.git"
clone_tool "zmap" "https://github.com/zmap/zmap.git"
clone_tool "john" "https://github.com/openwall/john.git"
clone_tool "hashcat" "https://github.com/hashcat/hashcat.git"
clone_tool "thc-hydra" "https://github.com/vanhauser-thc/thc-hydra.git"
clone_tool "XSStrike" "https://github.com/s0md3v/XSStrike.git"
clone_tool "zaproxy" "https://github.com/zaproxy/zaproxy.git"
clone_tool "aircrack-ng" "https://github.com/aircrack-ng/aircrack-ng.git"
clone_tool "gophish" "https://github.com/gophish/gophish.git"
clone_tool "volatility" "https://github.com/volatilityfoundation/volatility.git"
clone_tool "mimikatz" "https://github.com/gentilkiwi/mimikatz.git"
clone_tool "openvas" "https://github.com/greenbone/openvas-scanner.git"

# Créer répertoires personnalisés
echo ""
echo "📁 Création des répertoires personnalisés..."
mkdir -p scanners wordlists anydesk-backdoor rustdesk reverse-engineer-tool

# Créer un scanner réseau basique
cat > scanners/network_scanner.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys
from datetime import datetime

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_host(host, ports):
    print(f"[*] Scanning {host}...")
    print(f"[*] Started at {datetime.now()}")
    open_ports = []
    for port in ports:
        if scan_port(host, port):
            open_ports.append(port)
            print(f"[+] Port {port} is OPEN")
    print(f"\n[*] Scan completed at {datetime.now()}")
    print(f"[*] Found {len(open_ports)} open ports")
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python network_scanner.py <host>")
        sys.exit(1)
    host = sys.argv[1]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    scan_host(host, common_ports)
EOF

chmod +x scanners/network_scanner.py

# Créer une wordlist basique
cat > wordlists/common_passwords.txt << 'EOF'
admin
password
123456
password123
admin123
root
toor
administrator
letmein
welcome
qwerty
EOF

echo ""
echo "============================================"
echo "✅ Installation terminée!"
echo "============================================"
echo ""
echo "📊 Outils installés dans: /var/www/qatar-one/tools"
echo "📝 Nombre d'outils: $(ls -d */ 2>/dev/null | wc -l)"
echo ""
