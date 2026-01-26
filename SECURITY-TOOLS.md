# Security Tools - Alpha AI Platform

## 📋 Liste des Outils de Sécurité

Les outils de sécurité suivants étaient précédemment inclus comme sous-modules Git dans le répertoire `tools/`. Ils ont été retirés du repository pour réduire la taille et éviter les problèmes de sous-modules.

### 🔧 Outils Disponibles

#### Exploitation & Post-Exploitation
- **Metasploit Framework** - Framework de test de pénétration
- **Mimikatz** - Extraction de credentials Windows
- **PowerSploit** - Collection de modules PowerShell pour post-exploitation
- **BeEF** - Browser Exploitation Framework

#### Scanning & Reconnaissance
- **Nmap** - Scanner de réseau et de ports
- **Nikto** - Scanner de vulnérabilités web
- **OpenVAS** - Scanner de vulnérabilités
- **Recon-ng** - Framework de reconnaissance
- **SpiderFoot** - OSINT automation
- **theHarvester** - Collecte d'informations OSINT
- **ZMap** - Scanner de réseau haute vitesse

#### Password Cracking
- **John the Ripper** - Craqueur de mots de passe
- **Hashcat** - Craqueur de hash avancé
- **THC-Hydra** - Brute force de services réseau

#### Web Application Testing
- **SQLMap** - Injection SQL automatisée
- **XSStrike** - Détection et exploitation XSS
- **ZAP (OWASP ZAP)** - Proxy de sécurité web

#### Wireless
- **Aircrack-ng** - Suite d'outils WiFi

#### Remote Access
- **GoPhish** - Framework de phishing
- **AnyDesk Backdoor** - Outil de backdoor AnyDesk
- **RustDesk** - Alternative open-source à TeamViewer

#### Forensics
- **Volatility** - Framework d'analyse mémoire

#### Custom Tools
- **Reverse Engineer Tool** - Outil de reverse engineering personnalisé
- **Network Scanner** - Scanner réseau personnalisé

## 🚀 Installation

### Option 1: Installation Manuelle

Pour réinstaller un outil spécifique, clonez-le dans le répertoire `tools/`:

```bash
# Exemple: Metasploit
cd tools
git clone https://github.com/rapid7/metasploit-framework.git

# Exemple: SQLMap
git clone https://github.com/sqlmapproject/sqlmap.git

# Exemple: Nmap (via package manager)
sudo apt install nmap
```

### Option 2: Script d'Installation Automatique

Créez un script `install-security-tools.sh` pour installer tous les outils nécessaires:

```bash
#!/bin/bash

# Créer le répertoire tools
mkdir -p tools
cd tools

# Cloner les outils depuis GitHub
git clone https://github.com/rapid7/metasploit-framework.git
git clone https://github.com/sqlmapproject/sqlmap.git
git clone https://github.com/PowerShellMafia/PowerSploit.git
git clone https://github.com/beefproject/beef.git
# ... etc

echo "✅ Outils de sécurité installés"
```

## ⚠️ Avertissement

Ces outils sont destinés à des fins de test de sécurité légitimes uniquement. L'utilisation non autorisée de ces outils peut être illégale. Assurez-vous d'avoir l'autorisation appropriée avant d'effectuer des tests de sécurité.

## 📚 Documentation

Pour plus d'informations sur chaque outil, consultez:
- Documentation officielle de chaque projet
- Guides de test de pénétration
- Certifications de sécurité (OSCP, CEH, etc.)

## 🔗 Liens Utiles

- [Metasploit](https://www.metasploit.com/)
- [Kali Linux Tools](https://www.kali.org/tools/)
- [OWASP](https://owasp.org/)
- [Offensive Security](https://www.offensive-security.com/)

---

**Note:** Les outils ne sont plus inclus dans le repository Git pour des raisons de taille et de maintenance. Installez-les localement selon vos besoins.
