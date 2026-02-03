# 🚀 Alpha AI v2.0 - Guide de Déploiement Complet

## 📋 Table des Matières

1. [Déploiement avec Docker](#déploiement-avec-docker)
2. [CI/CD avec GitHub Actions](#cicd-avec-github-actions)
3. [Monitoring avec Prometheus & Grafana](#monitoring-avec-prometheus--grafana)
4. [Déploiement Manuel](#déploiement-manuel)
5. [Troubleshooting](#troubleshooting)

---

## 🐳 Déploiement avec Docker

### Prérequis

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 20GB espace disque

### Installation Rapide

```bash
# 1. Cloner le repository
git clone https://github.com/Shahil-AppDev/Alpha-AI-V2.git
cd Alpha-AI-V2

# 2. Configurer les variables d'environnement
cp .env.docker .env
nano .env  # Modifier avec vos valeurs

# 3. Lancer tous les services
docker-compose up -d

# 4. Vérifier le statut
docker-compose ps

# 5. Voir les logs
docker-compose logs -f backend
```

### Services Déployés

| Service | Port | Description |
|---------|------|-------------|
| **Backend** | 3001 | API NestJS |
| **PostgreSQL** | 5433 | Base de données |
| **Prometheus** | 9090 | Collecte de métriques |
| **Grafana** | 3000 | Visualisation |
| **Redis** | 6379 | Cache |
| **Node Exporter** | 9100 | Métriques système |

### Commandes Utiles

```bash
# Démarrer tous les services
docker-compose up -d

# Arrêter tous les services
docker-compose down

# Redémarrer un service spécifique
docker-compose restart backend

# Voir les logs d'un service
docker-compose logs -f backend

# Exécuter une commande dans un container
docker-compose exec backend npm run prisma:migrate

# Reconstruire les images
docker-compose build --no-cache

# Nettoyer les volumes (ATTENTION: supprime les données)
docker-compose down -v
```

### Configuration Avancée

#### Personnaliser les ressources

Modifier `docker-compose.yml`:

```yaml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

#### Ajouter un réseau externe

```yaml
networks:
  alpha-ai-network:
    external: true
    name: production-network
```

---

## 🔄 CI/CD avec GitHub Actions

### Configuration Initiale

#### 1. Secrets GitHub à configurer

Aller dans **Settings > Secrets and variables > Actions** et ajouter:

```
SSH_PRIVATE_KEY: Votre clé SSH privée pour le serveur
POSTGRES_PASSWORD: Mot de passe PostgreSQL
JWT_SECRET: Secret JWT
OPENCLAW_TOKEN: Token OpenClaw
REDIS_PASSWORD: Mot de passe Redis
GRAFANA_ADMIN_PASSWORD: Mot de passe admin Grafana
```

#### 2. Activer GitHub Actions

Les workflows sont déjà configurés dans `.github/workflows/`:

- **ci-cd.yml**: Pipeline complet (test, build, deploy)
- **docker-build.yml**: Build et push des images Docker

### Workflows Disponibles

#### Pipeline CI/CD Principal

**Déclenché sur**: Push sur `main` ou `develop`, Pull Requests

**Étapes**:
1. ✅ Test Backend (lint, tests unitaires, build)
2. ✅ Test Frontend (lint, build)
3. ✅ Build Docker Images (si push sur main)
4. ✅ Deploy Production (si push sur main)
5. ✅ Security Scan (Trivy + npm audit)

#### Build Docker

**Déclenché sur**: Push sur `main`, Tags `v*`

**Étapes**:
1. Build images multi-architecture (amd64, arm64)
2. Push vers GitHub Container Registry
3. Cache optimisé avec GitHub Actions

### Déploiement Automatique

Chaque push sur `main` déclenche automatiquement:

```
1. Tests → 2. Build → 3. Deploy → 4. Health Check
```

**Rollback automatique** si le health check échoue.

### Utilisation Manuelle

```bash
# Déclencher un déploiement manuel
git tag v1.0.0
git push origin v1.0.0

# Voir les logs du workflow
gh run list
gh run view <run-id>

# Annuler un workflow en cours
gh run cancel <run-id>
```

---

## 📊 Monitoring avec Prometheus & Grafana

### Accès aux Dashboards

#### Prometheus
- **URL**: http://localhost:9090
- **Métriques disponibles**: 
  - `http_requests_total`
  - `node_cpu_seconds_total`
  - `node_memory_MemAvailable_bytes`
  - `process_resident_memory_bytes`

#### Grafana
- **URL**: http://localhost:3000
- **Login**: admin / Admin@2026 (configurable dans `.env`)
- **Dashboard**: "Alpha AI v2.0 - System Overview"

### Métriques Surveillées

#### Backend NestJS
- Requêtes HTTP (rate, durée, erreurs)
- Utilisation mémoire
- Temps de réponse API
- Taux d'erreur

#### Système
- CPU usage
- Mémoire RAM
- Espace disque
- I/O réseau

#### Base de données
- Connexions actives
- Requêtes par seconde
- Temps de requête moyen
- Cache hit ratio

### Alertes Configurées

Les alertes sont envoyées si:
- CPU > 90% pendant 5 minutes
- Mémoire > 85% pendant 5 minutes
- Espace disque < 10%
- Backend down pendant 1 minute
- Taux d'erreur > 5%

### Ajouter des Métriques Personnalisées

Dans votre code NestJS:

```typescript
import { Counter, Histogram } from 'prom-client';

// Compteur de requêtes
const httpRequestCounter = new Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status']
});

// Histogramme de durée
const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'HTTP request duration',
  labelNames: ['method', 'route']
});

// Utilisation
httpRequestCounter.inc({ method: 'GET', route: '/api/agents', status: 200 });
```

### Exporter les Dashboards

```bash
# Exporter un dashboard Grafana
curl -H "Authorization: Bearer <API_KEY>" \
  http://localhost:3000/api/dashboards/uid/alpha-ai-overview \
  > dashboard-backup.json

# Importer un dashboard
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer <API_KEY>" \
  -d @dashboard-backup.json \
  http://localhost:3000/api/dashboards/db
```

---

## 🔧 Déploiement Manuel

### Sur le Serveur de Production

#### 1. Prérequis

```bash
# Installer Node.js 20+
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Installer PM2
sudo npm install -g pm2

# Installer PostgreSQL
sudo apt install -y postgresql postgresql-contrib

# Installer Nginx
sudo apt install -y nginx

# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh
```

#### 2. Configuration Base de Données

```bash
sudo -u postgres psql << EOF
CREATE DATABASE qatardb;
CREATE USER qataruser WITH PASSWORD 'securepassword';
GRANT ALL PRIVILEGES ON DATABASE qatardb TO qataruser;
EOF
```

#### 3. Déploiement Backend

```bash
# Cloner le repository
git clone https://github.com/Shahil-AppDev/Alpha-AI-V2.git /var/www/qatar-one
cd /var/www/qatar-one/apps/backend

# Installer les dépendances
npm install --production

# Configurer .env
cp .env.example .env
nano .env

# Migrations
npx prisma migrate deploy
npx prisma db seed

# Build
npm run build

# Démarrer avec PM2
pm2 start dist/main.js --name qatar-one-backend
pm2 save
pm2 startup
```

#### 4. Déploiement Frontend

```bash
cd /var/www/qatar-one/apps/frontend

# Installer et build
npm install --production
npm run build
npm run export

# Configurer Nginx
sudo cp nginx.conf /etc/nginx/sites-available/qatar-one
sudo ln -s /etc/nginx/sites-available/qatar-one /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### 5. SSL avec Let's Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d qatar-one.app
sudo certbot renew --dry-run
```

---

## 🐛 Troubleshooting

### Backend ne démarre pas

```bash
# Vérifier les logs
pm2 logs qatar-one-backend

# Vérifier la connexion DB
psql -U qataruser -d qatardb -h localhost -p 5433

# Vérifier les variables d'environnement
pm2 env 0

# Redémarrer
pm2 restart qatar-one-backend
```

### Docker containers ne démarrent pas

```bash
# Vérifier les logs
docker-compose logs backend

# Vérifier l'espace disque
df -h

# Nettoyer Docker
docker system prune -a

# Reconstruire
docker-compose build --no-cache
docker-compose up -d
```

### Prometheus ne collecte pas de métriques

```bash
# Vérifier la config
docker-compose exec prometheus cat /etc/prometheus/prometheus.yml

# Tester les targets
curl http://localhost:9090/api/v1/targets

# Vérifier les logs
docker-compose logs prometheus
```

### Grafana ne se connecte pas à Prometheus

```bash
# Vérifier la datasource
curl http://localhost:3000/api/datasources

# Tester la connexion
docker-compose exec grafana curl http://prometheus:9090/api/v1/query?query=up

# Reconfigurer
docker-compose restart grafana
```

### Déploiement GitHub Actions échoue

```bash
# Vérifier les secrets
gh secret list

# Tester la connexion SSH
ssh -i <key> root@157.180.107.154

# Voir les logs détaillés
gh run view <run-id> --log
```

---

## 📚 Ressources Supplémentaires

### Documentation

- [Docker Compose Reference](https://docs.docker.com/compose/)
- [GitHub Actions Documentation](https://docs.github.com/actions)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)

### Commandes de Maintenance

```bash
# Backup base de données
pg_dump -U qataruser qatardb > backup.sql

# Restore base de données
psql -U qataruser qatardb < backup.sql

# Backup volumes Docker
docker run --rm -v alpha-ai-postgres-data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-backup.tar.gz /data

# Nettoyer les logs PM2
pm2 flush

# Mettre à jour les dépendances
npm update
npm audit fix
```

---

## ✅ Checklist de Déploiement

### Avant le déploiement

- [ ] Tous les tests passent
- [ ] Variables d'environnement configurées
- [ ] Secrets GitHub configurés
- [ ] Base de données sauvegardée
- [ ] SSL certificat valide

### Après le déploiement

- [ ] Health check réussi
- [ ] Logs sans erreurs
- [ ] Métriques Prometheus collectées
- [ ] Dashboard Grafana accessible
- [ ] Frontend accessible
- [ ] API répond correctement

---

**Version**: 2.0  
**Dernière mise à jour**: 3 Février 2026  
**Statut**: Production Ready ✅
