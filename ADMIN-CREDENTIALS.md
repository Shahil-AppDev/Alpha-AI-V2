# Identifiants Administrateur - Alpha AI

## 🔐 Accès Admin

### URL de Connexion
**Local**: http://localhost:3000/admin/login
**Production**: http://157.180.107.154/admin/login

### Identifiants par Défaut

```
Nom d'utilisateur: admin
Mot de passe: AlphaAI2026!Secure
Email: admin@alpha-ai.com
```

## 📋 Fonctionnalités Admin

### Dashboard Admin
- **Outils de Sécurité**: Accès aux outils de cybersécurité (Metasploit, Nmap, SQLMap, etc.)
- **Statistiques**: Vue d'ensemble du système
- **IA & Agents**: Gestion des agents IA
- **Serveur**: Monitoring du serveur (IP: 157.180.107.154)
- **Déploiement**: Accès direct aux GitHub Actions
- **Paramètres**: Configuration système

## 🔒 Sécurité

### Changer le Mot de Passe
Pour changer le mot de passe admin, modifiez le fichier `.env.local`:

```bash
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VotreNouveauMotDePasse
ADMIN_EMAIL=admin@alpha-ai.com
```

### JWT Secret
Le secret JWT est utilisé pour signer les tokens d'authentification:
```bash
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-2026
```

**⚠️ IMPORTANT**: Changez ces valeurs en production!

## 🚀 Déploiement

### Variables d'Environnement Serveur
Ajoutez ces variables sur votre serveur dans `/var/www/alpha-ai/frontend/.env.local`:

```bash
ADMIN_USERNAME=admin
ADMIN_PASSWORD=AlphaAI2026!Secure
ADMIN_EMAIL=admin@alpha-ai.com
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-2026
SESSION_SECRET=alpha-ai-session-secret-key-2026
```

## 📝 Notes

- Le token JWT expire après 24 heures
- L'authentification est stockée dans localStorage
- Déconnexion automatique si le token est invalide
- Interface responsive et moderne avec Tailwind CSS

## 🔗 Liens Utiles

- **Dashboard**: `/admin/dashboard`
- **Login**: `/admin/login`
- **GitHub Actions**: https://github.com/Shahil-AppDev/Alpha-AI-V2/actions
- **Serveur**: http://157.180.107.154
