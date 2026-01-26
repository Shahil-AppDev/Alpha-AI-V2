# Configuration GitHub Actions - Déploiement Automatique

## 🔑 Clé SSH Générée

Une paire de clés SSH a été créée pour permettre à GitHub Actions de se connecter au serveur sans mot de passe.

**Fichiers créés:**
- `github-deploy-key` - Clé privée (à configurer dans GitHub Secrets)
- `github-deploy-key.pub` - Clé publique (déjà installée sur le serveur)

**Statut:** ✅ Clé publique installée sur `root@157.180.107.154`

## 📋 Configuration des Secrets GitHub

Pour activer le déploiement automatique, vous devez configurer les secrets suivants dans votre repository GitHub:

### Étapes de configuration:

1. **Accédez aux paramètres du repository:**
   - Allez sur GitHub.com
   - Ouvrez votre repository `Alpha AI V2`
   - Cliquez sur `Settings` > `Secrets and variables` > `Actions`

2. **Ajoutez les secrets suivants:**

#### Secret 1: SSH_PRIVATE_KEY
```bash
# Copiez le contenu de la clé privée
cat github-deploy-key
```
- **Name:** `SSH_PRIVATE_KEY`
- **Value:** Collez tout le contenu du fichier `github-deploy-key` (incluant `-----BEGIN OPENSSH PRIVATE KEY-----` et `-----END OPENSSH PRIVATE KEY-----`)

#### Secret 2: SERVER_HOST
- **Name:** `SERVER_HOST`
- **Value:** `157.180.107.154`

### Commande rapide pour copier la clé privée:
```powershell
# Windows PowerShell
Get-Content github-deploy-key | Set-Clipboard
# La clé est maintenant dans votre presse-papier
```

## 🚀 Workflow GitHub Actions

Le workflow `deploy.yml` a été créé dans `.github/workflows/deploy.yml`

### Déclenchement automatique:
- ✅ Push sur la branche `main`
- ✅ Modifications dans `frontend/`, `apps/backend/`, ou `src/`
- ✅ Déclenchement manuel via GitHub UI

### Processus de déploiement:

1. **Build Frontend**
   - Installation des dépendances (`npm ci`)
   - Build Next.js avec `NEXT_PUBLIC_API_URL=https://api.qatar-one.app`
   - Création de l'archive `frontend-deploy.tar.gz`

2. **Build Backend**
   - Installation des dépendances (`npm ci`)
   - Build NestJS
   - Création de l'archive `backend-deploy.tar.gz` (incluant dist, package.json, prisma)

3. **Déploiement sur le serveur**
   - Transfert des archives via SCP
   - Extraction dans `/var/www/qatar-one/`
   - Installation des dépendances de production
   - Génération du Prisma Client
   - Application des migrations
   - Redémarrage du backend avec PM2

4. **Vérification**
   - Test du health check (`/health`)
   - Affichage du statut PM2

## 📝 Utilisation

### Déploiement automatique:
```bash
# Commitez et pushez vos changements
git add .
git commit -m "feat: nouvelle fonctionnalité"
git push origin main

# GitHub Actions déploiera automatiquement
```

### Déploiement manuel:
1. Allez sur GitHub.com
2. Ouvrez votre repository
3. Cliquez sur `Actions`
4. Sélectionnez le workflow `Deploy Qatar One Platform`
5. Cliquez sur `Run workflow`

## 🔍 Monitoring

### Voir les logs de déploiement:
1. Allez dans l'onglet `Actions` de votre repository
2. Cliquez sur le workflow en cours d'exécution
3. Consultez les logs de chaque étape

### Vérifier le déploiement:
```bash
# Vérifier le backend
curl https://api.qatar-one.app/health

# Vérifier le frontend
curl -I https://qatar-one.app

# Vérifier PM2 sur le serveur
ssh -i github-deploy-key root@157.180.107.154 "pm2 status"
```

## 🔐 Sécurité

### Bonnes pratiques:
- ✅ La clé privée est stockée uniquement dans GitHub Secrets (chiffrée)
- ✅ La clé publique est installée sur le serveur
- ✅ La clé est automatiquement nettoyée après chaque déploiement
- ✅ Connexion SSH sans mot de passe (authentification par clé)

### Important:
- ⚠️ **NE JAMAIS** commiter la clé privée (`github-deploy-key`) dans Git
- ⚠️ Le fichier est déjà dans `.gitignore`
- ⚠️ Gardez la clé privée en sécurité localement

## 📊 URLs de l'application

Après déploiement, l'application est accessible sur:
- **Frontend:** https://qatar-one.app
- **Admin:** https://qatar-one.app/admin
- **API:** https://api.qatar-one.app
- **Auth:** https://qatar-one.app/auth

## 🛠️ Dépannage

### Le déploiement échoue:
1. Vérifiez que les secrets GitHub sont correctement configurés
2. Consultez les logs dans l'onglet Actions
3. Vérifiez que le serveur est accessible

### Tester la connexion SSH localement:
```bash
ssh -i github-deploy-key root@157.180.107.154 "echo 'Connection OK'"
```

### Redéployer manuellement:
```bash
# Si GitHub Actions échoue, utilisez le script local
.\deploy-qatar-fixed.ps1
```

## 📞 Support

En cas de problème:
1. Consultez les logs GitHub Actions
2. Vérifiez les logs du serveur: `pm2 logs qatar-one-backend`
3. Vérifiez la connexion SSH
4. Contactez l'administrateur système

## ✅ Checklist de configuration

- [x] Clé SSH générée
- [x] Clé publique installée sur le serveur
- [x] Workflow GitHub Actions créé
- [ ] Secret `SSH_PRIVATE_KEY` configuré dans GitHub
- [ ] Secret `SERVER_HOST` configuré dans GitHub
- [ ] Premier déploiement testé

## 🎯 Prochaines étapes

1. **Configurez les secrets GitHub** (voir section ci-dessus)
2. **Testez le déploiement** en poussant un commit
3. **Vérifiez** que l'application fonctionne après déploiement

---

**Date de création:** 26 janvier 2026
**Serveur:** 157.180.107.154
**Projet:** Alpha AI V2 - Qatar One Platform
