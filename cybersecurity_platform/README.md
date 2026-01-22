# Enhanced Cybersecurity Platform with Kali Tools

Plateforme de cybersécurité complète intégrant les outils Kali Linux, l'IA pour la détection de vulnérabilités, et un système de mise à jour automatique pour VPS.

## 🎯 Fonctionnalités Principales

### Intégration des Outils Kali Linux

- **Nmap** - Scanner réseau avancé
- **Metasploit** - Framework d'exploitation
- **Burp Suite** - Scanner d'applications web
- **Wireshark** - Analyseur de protocoles réseau
- **John the Ripper** - Craqueur de mots de passe

### Intelligence Artificielle

- **Scanner de Vulnérabilités IA** - Détection automatique des failles de sécurité
- **Détection d'Intrusion IA** - Analyse du trafic réseau en temps réel
- **Threat Intelligence IA** - Analyse des indicateurs de menace

### Système de Mise à Jour Automatique

- Mises à jour planifiées (quotidien, hebdomadaire, mensuel)
- Fenêtre de maintenance configurable
- Gestion des dépendances
- Rollback automatique en cas d'échec

### Monitoring de Sécurité

- Surveillance système en temps réel
- Alertes configurables
- Historique des événements
- Tableaux de bord de sécurité

## 📦 Installation

```bash
# Cloner le repository
git clone https://github.com/Shahil-AppDev/Alpha-AI-V2.git
cd Alpha-AI-V2/cybersecurity_platform

# Installer les dépendances
pip install -r requirements.txt

# Configuration
cp config/default_config.py config/config.py
# Éditer config/config.py selon vos besoins
```

## 🚀 Démarrage Rapide

```python
from cybersecurity_platform import CybersecurityPlatform

# Configuration de la plateforme
config = {
    'kali_tools': {
        'nmap': {'enabled': True, 'version': 'latest'},
        'metasploit': {'enabled': True, 'version': 'latest'},
        'burpsuite': {'enabled': True, 'version': 'latest'},
        'wireshark': {'enabled': True, 'version': 'latest'},
        'john': {'enabled': True, 'version': 'latest'}
    },
    'ai_models': {
        'ai_vulnerability_scanner': {'enabled': True},
        'ai_intrusion_detection': {'enabled': True},
        'ai_threat_intelligence': {'enabled': True}
    },
    'update_system': {
        'update_frequency': 'daily',
        'update_window': {'start': '02:00', 'end': '04:00'}
    },
    'security_monitoring': {
        'monitoring_interval': 60,
        'monitoring_services': {
            'system_monitoring': {'enabled': True, 'interval': 60},
            'tool_monitoring': {'enabled': True, 'interval': 120},
            'ai_model_monitoring': {'enabled': True, 'interval': 180}
        }
    }
}

# Créer et démarrer la plateforme
platform = CybersecurityPlatform(config)
platform.start()

# Exemple: Scanner réseau avec Nmap
nmap_tool = platform.get_tool('nmap')
results = nmap_tool.scan('192.168.1.0/24', {
    'scan_type': 'quick',
    'os_detection': True,
    'service_version': True
})
print(f"Scan results: {results}")

# Exemple: Scanner de vulnérabilités IA
ai_scanner = platform.get_ai_model('ai_vulnerability_scanner')
vulnerabilities = ai_scanner.scan('example.com', {'depth': 'deep'})
print(f"Vulnerabilities found: {vulnerabilities['vulnerabilities_found']}")

# Exemple: Obtenir le statut de la plateforme
status = platform.get_status()
print(f"Platform status: {status}")

# Arrêter la plateforme
platform.stop()
```

## 🔧 Configuration

### Outils Kali

```python
'kali_tools': {
    'nmap': {
        'enabled': True,
        'category': 'network',
        'version': 'latest',
        'update_frequency': 'daily'
    },
    'metasploit': {
        'enabled': True,
        'category': 'exploitation',
        'version': 'latest',
        'update_frequency': 'daily'
    }
    # ... autres outils
}
```

### Modèles IA

```python
'ai_models': {
    'ai_vulnerability_scanner': {
        'enabled': True,
        'category': 'vulnerability_scanning',
        'version': 'latest',
        'model_path': '/path/to/model',
        'training_data': '/path/to/data'
    }
    # ... autres modèles
}
```

### Système de Mise à Jour

```python
'update_system': {
    'update_frequency': 'daily',  # 'daily', 'weekly', 'monthly'
    'update_window': {
        'start': '02:00',
        'end': '04:00'
    }
}
```

## 📊 API REST

### Endpoints Disponibles

#### POST /scan
Exécuter un scan de sécurité

```json
{
  "scan_type": "nmap",
  "target": "192.168.1.1",
  "options": {
    "scan_type": "quick",
    "os_detection": true
  }
}
```

#### GET /tools
Lister tous les outils disponibles

#### GET /ai-models
Lister tous les modèles IA disponibles

#### GET /status
Obtenir le statut de la plateforme

#### GET /alerts
Obtenir les alertes de sécurité

```json
{
  "severity": "high",
  "service": "system_monitoring"
}
```

#### POST /update
Forcer une mise à jour immédiate

## 🔍 Types de Scans Disponibles

### Scans Nmap

- **quick** - Scan rapide des ports communs
- **intense** - Scan approfondi avec détection OS
- **stealth** - Scan furtif
- **comprehensive** - Scan complet de tous les ports

### Scans IA

- **vulnerability** - Détection de vulnérabilités
- **intrusion_detection** - Analyse d'intrusion
- **threat_intelligence** - Intelligence sur les menaces

## 📈 Monitoring et Alertes

### Niveaux de Sévérité

- **critical** - Nécessite une action immédiate
- **high** - Problème important
- **medium** - Attention requise
- **low** - Information

### Services de Monitoring

- **system_monitoring** - CPU, mémoire, disque
- **tool_monitoring** - État des outils Kali
- **ai_model_monitoring** - Performance des modèles IA
- **security_monitoring** - Événements de sécurité

## 🛡️ Sécurité

- Validation des entrées
- Logs d'audit complets
- Isolation des processus
- Chiffrement des données sensibles
- Gestion des permissions

## 📝 Logs

Les logs sont disponibles dans:
- `/var/log/cybersecurity_platform/platform.log`
- `/var/log/cybersecurity_platform/tools.log`
- `/var/log/cybersecurity_platform/ai.log`
- `/var/log/cybersecurity_platform/monitoring.log`

## 🔄 Mises à Jour

### Forcer une Mise à Jour

```python
update_system = platform.get_service('update_system')
update_system.force_update()
```

### Configurer la Fréquence

```python
update_system.set_update_frequency('weekly')
update_system.set_update_window('03:00', '05:00')
```

### Consulter l'Historique

```python
update_log = update_system.get_update_log(limit=10)
```

## 🎓 Cas d'Usage

### Audit de Sécurité Complet

```python
# Scanner réseau
nmap_results = platform.execute_scan('nmap', '192.168.1.0/24', {
    'scan_type': 'comprehensive'
})

# Analyse de vulnérabilités IA
vuln_results = platform.execute_scan('vulnerability', '192.168.1.10', {
    'depth': 'deep'
})

# Détection d'intrusion
intrusion_results = platform.execute_scan('intrusion_detection', '192.168.1.0/24')
```

### Pentest Automatisé

```python
# Recherche d'exploits
metasploit = platform.get_tool('metasploit')
exploits = metasploit.search_exploits('apache')

# Test d'application web
burpsuite = platform.get_tool('burpsuite')
web_scan = burpsuite.scan_web_app('https://target.com')
```

### Monitoring Continu

```python
# Obtenir les alertes
monitoring = platform.get_service('security_monitoring')
alerts = monitoring.get_alerts(severity='high')

# Accuser réception
for alert in alerts:
    monitoring.acknowledge_alert(alert['alert_id'])
```

## 🤝 Contribution

Ce projet fait partie de l'écosystème **Business Services IDF** (Shahil AppDev).

## 📄 Licence

MIT License

## 👨‍💻 Auteur

**Shahil AppDev** - Business Services IDF
- Services CYBER: audit, pentest, hardening, monitoring, RGPD
- Contact: [Votre contact]

## 🔗 Liens Utiles

- [Documentation Kali Linux](https://www.kali.org/docs/)
- [Metasploit Framework](https://www.metasploit.com/)
- [Nmap Reference Guide](https://nmap.org/book/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
