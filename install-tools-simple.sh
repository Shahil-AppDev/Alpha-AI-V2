#!/bin/bash
# Installation rapide des outils de sécurité

echo "Installation des outils de securite..."

mkdir -p /var/www/qatar-one/tools
cd /var/www/qatar-one/tools

# Cloner les outils
git clone --depth 1 https://github.com/rapid7/metasploit-framework.git &
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git &
git clone --depth 1 https://github.com/PowerShellMafia/PowerSploit.git &
git clone --depth 1 https://github.com/beefproject/beef.git &
git clone --depth 1 https://github.com/nmap/nmap.git &
git clone --depth 1 https://github.com/sullo/nikto.git &
git clone --depth 1 https://github.com/lanmaster53/recon-ng.git &
git clone --depth 1 https://github.com/smicallef/spiderfoot.git &
git clone --depth 1 https://github.com/laramies/theHarvester.git &
git clone --depth 1 https://github.com/zmap/zmap.git &

wait

git clone --depth 1 https://github.com/openwall/john.git &
git clone --depth 1 https://github.com/hashcat/hashcat.git &
git clone --depth 1 https://github.com/vanhauser-thc/thc-hydra.git &
git clone --depth 1 https://github.com/s0md3v/XSStrike.git &
git clone --depth 1 https://github.com/zaproxy/zaproxy.git &
git clone --depth 1 https://github.com/aircrack-ng/aircrack-ng.git &
git clone --depth 1 https://github.com/gophish/gophish.git &
git clone --depth 1 https://github.com/volatilityfoundation/volatility.git &
git clone --depth 1 https://github.com/gentilkiwi/mimikatz.git &
git clone --depth 1 https://github.com/greenbone/openvas-scanner.git &

wait

mkdir -p scanners wordlists anydesk-backdoor rustdesk reverse-engineer-tool

echo ""
echo "Installation terminee!"
echo "Outils installes: $(ls -d */ 2>/dev/null | wc -l)"
