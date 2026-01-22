# VPS Deployment Guide

Guide de déploiement de l'orchestrateur d'agents IA sur un VPS Kali Linux avec mises à jour automatiques des outils de sécurité.

## Prérequis

- VPS avec Kali Linux (ou Debian/Ubuntu)
- Accès root ou sudo
- Connexion Internet
- Au moins 2 GB RAM
- 20 GB d'espace disque

## Installation Rapide

```bash
# Télécharger le script d'installation
wget https://raw.githubusercontent.com/Shahil-AppDev/Alpha-AI-V2/main/orchestrator/deployment/vps_setup.sh

# Rendre exécutable
chmod +x vps_setup.sh

# Exécuter (nécessite root)
sudo ./vps_setup.sh
```

## Installation Manuelle

### 1. Mise à Jour du Système

```bash
apt-get update
apt-get upgrade -y
```

### 2. Installation des Dépendances

```bash
# Python et outils
apt-get install -y python3 python3-pip python3-venv git

# Outils de sécurité Kali
apt-get install -y \
    nmap \
    metasploit-framework \
    wireshark \
    tshark \
    burpsuite \
    suricata \
    john \
    hydra \
    sqlmap \
    nikto
```

### 3. Création de l'Utilisateur

```bash
useradd -m -s /bin/bash orchestrator
usermod -aG sudo orchestrator
```

### 4. Installation de l'Orchestrateur

```bash
# Créer les répertoires
mkdir -p /opt/orchestrator
mkdir -p /var/log/orchestrator
mkdir -p /backup/orchestrator

# Cloner le repository
cd /opt
git clone https://github.com/Shahil-AppDev/Alpha-AI-V2.git
cp -r Alpha-AI-V2/orchestrator/* /opt/orchestrator/

# Permissions
chown -R orchestrator:orchestrator /opt/orchestrator
chown -R orchestrator:orchestrator /var/log/orchestrator
```

### 5. Installation des Dépendances Python

```bash
cd /opt/orchestrator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 6. Configuration

```bash
# Copier la configuration par défaut
cp config/default_config.py config/config.py

# Éditer selon vos besoins
nano config/config.py
```

### 7. Configuration du Cron Job

```bash
# Éditer le fichier crontab
cp deployment/crontab.example /tmp/orchestrator-cron

# Remplacer les chemins
sed -i "s|/path/to/orchestrator|/opt/orchestrator|g" /tmp/orchestrator-cron

# Installer le crontab
crontab -u orchestrator /tmp/orchestrator-cron
```

### 8. Service Systemd

```bash
# Créer le service
cat > /etc/systemd/system/orchestrator.service <<EOF
[Unit]
Description=AI Agent Orchestrator
After=network.target

[Service]
Type=simple
User=orchestrator
WorkingDirectory=/opt/orchestrator
ExecStart=/opt/orchestrator/venv/bin/python3 /opt/orchestrator/orchestrator_main.py production
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Activer et démarrer
systemctl daemon-reload
systemctl enable orchestrator
systemctl start orchestrator
```

### 9. Firewall

```bash
# Autoriser SSH et API
ufw allow 22/tcp
ufw allow 8000/tcp
ufw --force enable
```

## Vérification

### Vérifier le Service

```bash
# Statut du service
systemctl status orchestrator

# Logs en temps réel
tail -f /var/log/orchestrator/platform.log

# Logs de mise à jour
tail -f /var/log/orchestrator/security_updates.log
```

### Tester l'API

```bash
# Statut de la plateforme
curl http://localhost:8000/status

# Liste des outils
curl http://localhost:8000/tools

# Liste des skills de sécurité
curl http://localhost:8000/security-skills
```

## Mises à Jour Automatiques

Les outils de sécurité sont mis à jour automatiquement tous les jours à 2h00 du matin via cron.

### Vérifier les Mises à Jour

```bash
# Vérifier manuellement
python3 /opt/orchestrator/utils/cron_updater.py

# Voir l'historique
cat /var/log/orchestrator/security_updates.log
```

### Modifier la Fréquence

Éditer le crontab:

```bash
crontab -e -u orchestrator
```

Exemples:
- Quotidien à 2h: `0 2 * * *`
- Hebdomadaire (dimanche): `0 2 * * 0`
- Deux fois par jour: `0 2,14 * * *`

## Sécurité

### Hardening Recommandé

```bash
# Désactiver root SSH
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Fail2ban
apt-get install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Mises à jour automatiques du système
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

### Monitoring

```bash
# Installer monitoring
apt-get install -y htop iotop nethogs

# Vérifier l'utilisation
htop
```

## Sauvegarde

### Sauvegarde Manuelle

```bash
# Configuration
tar -czf /backup/orchestrator-config-$(date +%Y%m%d).tar.gz /opt/orchestrator/config

# Logs
tar -czf /backup/orchestrator-logs-$(date +%Y%m%d).tar.gz /var/log/orchestrator

# Base de données (si applicable)
# pg_dump orchestrator_db > /backup/orchestrator-db-$(date +%Y%m%d).sql
```

### Restauration

```bash
# Restaurer configuration
tar -xzf /backup/orchestrator-config-YYYYMMDD.tar.gz -C /

# Restaurer logs
tar -xzf /backup/orchestrator-logs-YYYYMMDD.tar.gz -C /
```

## Dépannage

### Service ne Démarre Pas

```bash
# Vérifier les logs
journalctl -u orchestrator -n 50

# Vérifier les permissions
ls -la /opt/orchestrator

# Tester manuellement
cd /opt/orchestrator
source venv/bin/activate
python3 orchestrator_main.py development
```

### Outils de Sécurité Non Disponibles

```bash
# Vérifier l'installation
which nmap
which msfconsole
which tshark

# Réinstaller si nécessaire
apt-get install --reinstall nmap metasploit-framework wireshark
```

### Problèmes de Mise à Jour

```bash
# Vérifier les sources APT
cat /etc/apt/sources.list

# Nettoyer le cache
apt-get clean
apt-get update

# Forcer la mise à jour
apt-get install --only-upgrade -y nmap
```

## Performance

### Optimisation

```bash
# Augmenter les limites de fichiers
echo "orchestrator soft nofile 65536" >> /etc/security/limits.conf
echo "orchestrator hard nofile 65536" >> /etc/security/limits.conf

# Optimiser Python
export PYTHONOPTIMIZE=1
```

### Monitoring des Ressources

```bash
# CPU et mémoire
top -u orchestrator

# Disque
df -h
du -sh /opt/orchestrator/*

# Réseau
netstat -tulpn | grep python
```

## Support

Pour toute question ou problème:
- GitHub Issues: https://github.com/Shahil-AppDev/Alpha-AI-V2/issues
- Documentation: https://github.com/Shahil-AppDev/Alpha-AI-V2/wiki
- Email: [votre email]

## Licence

MIT License - Business Services IDF (Shahil AppDev)
