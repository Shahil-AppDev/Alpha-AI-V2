# 🤖 GUIDE COMPLET - AGENTS IA AVEC MIXTRAL 22B

## 🎯 RÉSUMÉ EXÉCUTIF

Système d'agents IA spécialisés en sécurité, alimentés par **Mixtral 22B** (Mixtral-8x22B-Instruct-v0.1), intégré au dashboard Qatar One. 5 agents spécialisés avec des capacités uniques pour l'offensive, la défense, et l'analyse de sécurité.

---

## 🤖 AGENTS DISPONIBLES

### **1. Red Team Agent** 🎯
- **Type**: Offensive Security
- **Statut**: Active
- **Modèle**: Mixtral-8x22B-Instruct-v0.1
- **Tâches**: 87 complétées
- **Taux de succès**: 87%

**Capacités**:
- Network penetration testing
- Vulnerability exploitation
- Social engineering
- Payload generation
- Attack simulation

**Prompt système**: Pense comme un attaquant et identifie les vulnérabilités, les chemins d'exploitation et les faiblesses de sécurité.

---

### **2. Blue Team Agent** 🛡️
- **Type**: Defensive Security
- **Statut**: Active
- **Modèle**: Mixtral-8x22B-Instruct-v0.1
- **Tâches**: 234 complétées
- **Taux de succès**: 92%

**Capacités**:
- Threat detection
- Incident response
- Security monitoring
- Log analysis
- Defense strategy

**Prompt système**: Défends les systèmes et détecte les menaces. Analyse les événements de sécurité et fournis des stratégies défensives.

---

### **3. Purple Team Agent** 👁️
- **Type**: Collaborative Security
- **Statut**: Standby
- **Modèle**: Mixtral-8x22B-Instruct-v0.1
- **Tâches**: 18 complétées
- **Taux de succès**: 92%

**Capacités**:
- Joint exercises
- Attack validation
- Defense validation
- Gap analysis
- Improvement recommendations

**Prompt système**: Fait le pont entre la sécurité offensive et défensive. Valide les attaques et défenses, identifie les lacunes.

---

### **4. Black Hat Agent** 🔒
- **Type**: Advanced Threat Simulation
- **Statut**: Offline
- **Modèle**: Mixtral-8x22B-Instruct-v0.1
- **Tâches**: 67 complétées
- **Taux de succès**: 89%

**Capacités**:
- Advanced persistent threats
- Zero-day exploitation
- Malware analysis
- Threat intelligence
- Attack chain simulation

**Prompt système**: Simule des menaces persistantes avancées et des attaques sophistiquées. Pense comme un adversaire hautement qualifié.

---

### **5. LLM Agent** 💻
- **Type**: AI-Powered Analysis
- **Statut**: Active
- **Modèle**: Mixtral-8x22B-Instruct-v0.1
- **Tâches**: 156 complétées
- **Taux de succès**: 94%

**Capacités**:
- Code analysis
- Vulnerability assessment
- Report generation
- Natural language queries
- Automated recommendations

**Prompt système**: Fournis une analyse de sécurité alimentée par l'IA, revue de code, évaluation de vulnérabilités et recommandations automatisées.

---

## 🔧 CONFIGURATION BACKEND

### **Variables d'Environnement**

Ajouter dans `apps/backend/.env`:

```env
# Mixtral 22B Configuration for AI Agents
MIXTRAL_API_URL=http://localhost:8000/v1/chat/completions
MIXTRAL_MODEL=mixtralai/Mixtral-8x22B-Instruct-v0.1
```

### **Configuration Serveur Mixtral**

**Option 1: Serveur Local avec vLLM**
```bash
# Installer vLLM
pip install vllm

# Démarrer le serveur Mixtral 22B
vllm serve mixtralai/Mixtral-8x22B-Instruct-v0.1 \
  --host 0.0.0.0 \
  --port 8000 \
  --dtype auto \
  --max-model-len 8192
```

**Option 2: API Externe (Replicate, Together AI, etc.)**
```env
MIXTRAL_API_URL=https://api.together.xyz/v1/chat/completions
MIXTRAL_API_KEY=your_api_key_here
```

**Option 3: Ollama (Recommandé pour développement)**
```bash
# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Télécharger Mixtral
ollama pull mixtral:8x22b

# Démarrer le serveur
ollama serve

# URL pour .env
MIXTRAL_API_URL=http://localhost:11434/v1/chat/completions
```

---

## 📁 STRUCTURE DU MODULE

### **Backend**
```
apps/backend/src/modules/agents/
├── agents.module.ts       # Module NestJS
├── agents.service.ts      # Logique métier et appels Mixtral
├── agents.controller.ts   # Endpoints REST API
└── agents.gateway.ts      # WebSocket gateway
```

### **Frontend**
```
frontend/components/agents/
└── agents-panel.tsx       # Interface utilisateur des agents
```

---

## 🌐 API ENDPOINTS

### **REST API**

#### **GET /api/agents**
Récupère tous les agents et leurs statistiques.

**Response**:
```json
{
  "agents": [
    {
      "id": "red-team-1",
      "name": "Red Team Agent",
      "type": "red-team",
      "status": "active",
      "model": "mixtralai/Mixtral-8x22B-Instruct-v0.1",
      "description": "Offensive security operations...",
      "capabilities": ["Network penetration testing", ...],
      "stats": {
        "tasksCompleted": 87,
        "successRate": 87,
        "lastActivity": "2026-02-03T03:47:00.000Z"
      }
    }
  ],
  "stats": {
    "total": 5,
    "active": 3,
    "standby": 1,
    "offline": 1,
    "totalTasks": 562,
    "averageSuccessRate": 90.8,
    "model": "mixtralai/Mixtral-8x22B-Instruct-v0.1"
  }
}
```

#### **GET /api/agents/:id**
Récupère un agent spécifique.

#### **POST /api/agents/:id/execute**
Exécute une tâche avec un agent.

**Request**:
```json
{
  "task": "Analyze this network configuration for vulnerabilities"
}
```

**Response**:
```json
{
  "success": true,
  "result": {
    "agentId": "red-team-1",
    "agentName": "Red Team Agent",
    "task": "Analyze this network configuration...",
    "response": "Based on my analysis, I've identified 3 critical vulnerabilities...",
    "timestamp": "2026-02-03T03:47:00.000Z"
  }
}
```

#### **PATCH /api/agents/:id/status**
Met à jour le statut d'un agent.

**Request**:
```json
{
  "status": "active" | "standby" | "offline"
}
```

---

### **WebSocket Events**

**Namespace**: `/agents`

#### **Client → Server**

**`get_agents`**: Récupère la liste des agents
```javascript
socket.emit('get_agents');
```

**`execute_agent_task`**: Exécute une tâche
```javascript
socket.emit('execute_agent_task', {
  agentId: 'red-team-1',
  task: 'Scan this network for open ports'
});
```

**`update_agent_status`**: Met à jour le statut
```javascript
socket.emit('update_agent_status', {
  agentId: 'red-team-1',
  status: 'active'
});
```

#### **Server → Client**

**`agents_list`**: Liste des agents
**`agent_task_result`**: Résultat d'une tâche
**`agent_task_error`**: Erreur d'exécution
**`agent_activity`**: Notification d'activité
**`agent_status_updated`**: Statut mis à jour

---

## 🎨 UTILISATION FRONTEND

### **Ouvrir le Panneau des Agents**

1. Aller sur le dashboard: `https://qatar-one.app/dashboard`
2. Cliquer sur le bouton **"Manage Agents"** dans la section "Security Agents"
3. Le panneau s'ouvre avec la liste des 5 agents

### **Interagir avec un Agent**

1. **Sélectionner un agent** dans la liste de gauche
2. **Voir les détails**: capacités, modèle, statistiques
3. **Entrer une tâche** dans le champ de saisie
4. **Cliquer sur Send** ou appuyer sur **Enter**
5. **Voir la réponse** de Mixtral 22B en temps réel

### **Exemples de Tâches**

**Red Team Agent**:
```
- "Analyze this network configuration for vulnerabilities"
- "Generate a reverse shell payload for Linux x64"
- "Identify potential SQL injection points in this code"
- "Simulate a phishing attack scenario"
```

**Blue Team Agent**:
```
- "Analyze these logs for suspicious activity"
- "Recommend defensive measures for this vulnerability"
- "Create an incident response plan for ransomware"
- "Review this firewall configuration"
```

**LLM Agent**:
```
- "Review this code for security vulnerabilities"
- "Explain this CVE and its impact"
- "Generate a security report for this scan"
- "Translate this technical document"
```

---

## 🚀 DÉPLOIEMENT

### **1. Backend**

```bash
# Sur le serveur
cd /var/www/qatar-one/backend
git pull origin main

# Mettre à jour .env
echo "MIXTRAL_API_URL=http://localhost:8000/v1/chat/completions" >> .env
echo "MIXTRAL_MODEL=mixtralai/Mixtral-8x22B-Instruct-v0.1" >> .env

# Installer les dépendances (déjà présentes)
npm install

# Recompiler
npm run build

# Redémarrer PM2
pm2 restart qatar-one-backend
```

### **2. Frontend**

```bash
# Déployer le frontend
cd /tmp
rm -rf qatar-deploy
git clone https://github.com/Shahil-AppDev/Alpha-AI-V2.git qatar-deploy
cd qatar-deploy/frontend
npm install
npm run build
cp -r out/* /var/www/qatar-one/frontend/out/
```

### **3. Configurer Mixtral 22B**

**Option recommandée: Ollama**
```bash
# Installer Ollama sur le serveur
curl -fsSL https://ollama.com/install.sh | sh

# Télécharger Mixtral 22B
ollama pull mixtral:8x22b

# Créer un service systemd pour Ollama
sudo tee /etc/systemd/system/ollama.service > /dev/null <<EOF
[Unit]
Description=Ollama Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ollama serve
Restart=always
RestartSec=10
Environment="OLLAMA_HOST=0.0.0.0:11434"

[Install]
WantedBy=multi-user.target
EOF

# Démarrer Ollama
sudo systemctl daemon-reload
sudo systemctl enable ollama
sudo systemctl start ollama

# Vérifier
curl http://localhost:11434/v1/models
```

---

## 🧪 TESTS

### **Test Backend**

```bash
# Vérifier que le backend fonctionne
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://qatar-one.app/api/agents

# Tester l'exécution d'une tâche
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task":"Hello, test message"}' \
  https://qatar-one.app/api/agents/llm-agent-1/execute
```

### **Test Frontend**

1. Ouvrir `https://qatar-one.app/dashboard`
2. Cliquer sur "Manage Agents"
3. Sélectionner "LLM Agent"
4. Entrer: "Hello, can you help me with security?"
5. Vérifier la réponse de Mixtral 22B

---

## 📊 STATISTIQUES

### **Agents Créés**: 5
- Red Team Agent
- Blue Team Agent
- Purple Team Agent
- Black Hat Agent
- LLM Agent

### **Tâches Totales**: 562
### **Taux de Succès Moyen**: 90.8%
### **Modèle**: Mixtral-8x22B-Instruct-v0.1
### **Agents Actifs**: 3/5

---

## 🔐 SÉCURITÉ

### **Authentification**
- Tous les endpoints nécessitent un JWT token valide
- Protection par `JwtAuthGuard`
- Vérification des permissions utilisateur

### **Isolation des Agents**
- Chaque agent a son propre contexte et prompt système
- Les agents ne peuvent pas interférer entre eux
- Statuts indépendants (active/standby/offline)

### **Rate Limiting**
- Timeout de 30 secondes par requête Mixtral
- Max 2000 tokens par réponse
- Gestion des erreurs et retry logic

---

## 🐛 TROUBLESHOOTING

### **Problème: Agent ne répond pas**

**Vérifier**:
```bash
# 1. Backend fonctionne
pm2 status qatar-one-backend

# 2. Mixtral/Ollama fonctionne
curl http://localhost:8000/v1/models
# ou
curl http://localhost:11434/v1/models

# 3. Logs backend
pm2 logs qatar-one-backend

# 4. Variables d'environnement
cat /var/www/qatar-one/backend/.env | grep MIXTRAL
```

### **Problème: Erreur "Failed to call Mixtral"**

**Solutions**:
1. Vérifier que Mixtral/Ollama est démarré
2. Vérifier l'URL dans `.env`
3. Tester manuellement l'API Mixtral
4. Vérifier les logs du serveur Mixtral

### **Problème: Agent status "offline"**

**Solution**:
```bash
# Mettre à jour le statut via API
curl -X PATCH \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"active"}' \
  https://qatar-one.app/api/agents/red-team-1/status
```

---

## 📚 RESSOURCES

### **Mixtral 22B**
- **Modèle**: mixtralai/Mixtral-8x22B-Instruct-v0.1
- **Paramètres**: 141B (8 experts x 22B, 2 actifs)
- **Context**: 64K tokens
- **Performance**: État de l'art pour les tâches de sécurité

### **Documentation**
- Mixtral: https://mistral.ai/news/mixtral-8x22b/
- Ollama: https://ollama.com/library/mixtral
- vLLM: https://docs.vllm.ai/

### **Alternatives**
- **Together AI**: https://together.ai/
- **Replicate**: https://replicate.com/
- **Groq**: https://groq.com/ (ultra-rapide)

---

## ✅ CHECKLIST DE DÉPLOIEMENT

- [ ] Backend déployé avec AgentsModule
- [ ] Variables d'environnement Mixtral configurées
- [ ] Serveur Mixtral/Ollama démarré
- [ ] Frontend déployé avec AgentsPanel
- [ ] Test de connexion aux agents réussi
- [ ] Test d'exécution de tâche réussi
- [ ] Vérification des logs sans erreurs
- [ ] Documentation lue et comprise

---

## 🎉 CONCLUSION

Système d'agents IA complet avec Mixtral 22B intégré au dashboard Qatar One. 5 agents spécialisés prêts à exécuter des tâches de sécurité offensive, défensive, et analytique.

**Prochaines étapes**:
1. Configurer Mixtral 22B sur le serveur
2. Déployer backend et frontend
3. Tester les agents avec des tâches réelles
4. Monitorer les performances et ajuster

---

**Date**: 2026-02-03  
**Version**: 1.0.0  
**Commit**: b7af43e9  
**Auteur**: Shahil AppDev  
**Serveur**: qatar-one.app (157.180.107.154)
