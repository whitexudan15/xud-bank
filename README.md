# Xud-Bank — SecureDataMonitor

> **Application Web bancaire sécurisée avec moteur de surveillance événementielle en temps réel**  
> Université de Kara – FAST-LPSIC S6 | Programmation Événementielle & Cybersécurité | 2025-2026

---

## 📋 Table des matières

1. [Présentation](#-1-présentation)
2. [Architecture](#-2-architecture)
3. [Stack Technologique](#-3-stack-technologique)
4. [Structure du Projet](#-4-structure-du-projet)
5. [Modèle de Données](#-5-modèle-de-données)
6. [Identification et Rôles](#-6-identification-et-rôles)
7. [Moteur Événementiel](#-7-moteur-événementiel)
8. [Règles de Détection SOC](#-8-règles-de-détection-soc)
9. [Installation & Déploiement](#-9-installation--déploiement)
10. [Journalisation](#-10-journalisation)
11. [Tests des Triggers d'Événements](#-11-tests-des-triggers-dévénements)

---

## 🔍 1. Présentation

**XUD-Bank** est une application Web bancaire de démonstration destinée au personnel interne et aux clients. Elle intègre directement un moteur de détection d'intrusion appelé **SecureDataMonitor**. Ce composant agit comme un mini-SOC (Security Operations Center) qui surveille, détecte, et alerte en temps réel toute activité suspecte sur le backend.

### ✨ Fonctionnalités Clés

- **UI Premium** : Interface asynchrone moderne (Bootstrap 5, Jinja2, Chart.js) avec des layouts optimisés pour les tableaux de bord interactifs
- **Authentification asynchrone** : Hachage Bcrypt optimisé fonctionnant hors du thread principal pour éviter tout ralentissement réseau
- **Moteur événementiel (Pub/Sub)** : Modèle 100% découplé pour une scalabilité optimale
- **Détection des menaces** : 6 règles de détection (Brute force, exfiltration, SQLi...)
- **Surveillance Ultra-fluide (WebSocket)** : Tableau de bord supportant des centaines d'événements par seconde sans latence grâce au regroupement d'événements (`requestAnimationFrame`)

---

## 🏗️ 2. Architecture

Le projet combine deux design patterns :

### Layered Architecture (4 couches)

```
┌─────────────────────────────────────────────┐
│  PRÉSENTATION  routers/ + templates/        │  HTTP, vues HTML, WebSocket
├─────────────────────────────────────────────┤
│  MÉTIER        services/auth_service.py     │  Logique bancaire, Threadpool, Bcrypt
├─────────────────────────────────────────────┤
│  ÉVÉNEMENTIELLE events/dispatcher.py        │  Pub/Sub, détection, alertes asynchrones
├─────────────────────────────────────────────┤
│  PERSISTANCE   models/ + database.py        │  CRUD SQLAlchemy 2.0 (asyncpg)
└─────────────────────────────────────────────┘
```

### Event-Driven Pattern (Pub/Sub)

```
Router (app bancaire)
    │
    │  dispatcher.emit("login_failed", {...})
    ▼
EventDispatcher (Lancement des Tâches Asynchrones)
    │
    ├──▶ handle_failed_login()  ──▶  detection.check_brute_force()
    │                                logger.log_event()
    │                                logger.create_alert()  ──▶  WebSocket Broadcast
    │
    └──▶ [autres handlers spécialisés]
```

---

## 🛠️ 3. Stack Technologique

| Composant | Technologie | Détails |
|---|---|---|
| **Backend** | FastAPI (Python 3.11+) | Asynchrone natif |
| **Base de données** | PostgreSQL (Railway) | Driver haute performance `asyncpg` |
| **ORM** | SQLAlchemy 2.0 | Opérations totalement asynchrones |
| **Mots de passe** | Passlib (Bcrypt = 12) | Exécuté sur *Threadpool* (non-bloquant) |
| **Sessions** | itsdangerous | Cookies chiffrés et signés sans BDD |
| **WebSocket** | WebSockets natifs | Optimisation visuelle par Batching (`requestAnimationFrame`) |
| **Frontend** | HTML5 / Bootstrap 5 / JS | Interfaces dynamiques / Chart.js mis à jour en masse |
| **Logs** | logging.RotatingFileHandler | Fichiers rotatifs & BDD locale sync |

---

## 📁 4. Structure du Projet

```
xud-bank/
├── app/                              # Application Bancaire
│   ├── main.py                       # Point d'entrée, middlewares de sécurité
│   ├── database.py                   # Configuration Railway + Asyncpg
│   ├── models/                       # UUIDPK, Enum (utilisateurs, alertes, etc.)
│   ├── routers/                      # Routes d'accès (auth, data)
│   ├── services/                     # Métier (auth via threadpool)
│   └── templates/                    # Front public (login, register, data)
├── secureDataMonitor/                # SOC Moteur de Surveillance
│   ├── events/                       # Handles & Dispatcher
│   ├── services/                     # Détection de menaces / Logger
│   ├── routers/                      # REST API Admin & WebSockets
│   ├── templates/admin/              # Front SOC (dashboard, alerts, events)
│   └── static/js/ws_alerts.js        # Script de batching haute performance
├── logs/                             # Fichiers de log locaux
└── init_db.sql / requirements.txt    # Scripts SQL et dépendances
```

---

## 💾 5. Modèle de Données

Le modèle repose sur PostgreSQL (avec Railway) :

- **`users`** : UUID, identifiants, mot de passe hashé, rôles et gestion de verrouillage (`is_locked`)
- **`bank_accounts`** : Données cibles (soldes, niveau de classification "secret" etc.)
- **`security_events`** : Trace indélébile en base des actions (avec typage Enum)
- **`alerts`** : Alertes levées par le SOC, liées aux `security_events` déclencheurs
- **`login_attempts`** : Historique granulaire pour la prévention du brute-force (Règle 1) et de l'énumération (Règle 5)

*(Voir le schéma complet dans `init_db.sql`)*

---

## 👥 6. Identification et Rôles

Voici les identifiants de test. La navigation et les accès sont fortement restreints selon le rôle validé durant la phase de connexion.

| Username | Mot de passe | Rôle | Accès & Privilèges |
|---|---|---|---|
| **`admin`** | `Admin@1234` | **admin (SOC)** | Accès complet, Dashboard Temps réel |
| **`soc`** | `Soc@1234` | **admin (SOC)** | Tableau de gestion des Alertes |
| **`hor`** | `Hor@1234` | **comptable** | Accès aux bilans |
| **`directeur`** | `Directeur@1234` | **directeur** | Accès directoire |
| **`dupont`** | `Dupont@1234` | **utilisateur (client)** | Consultation comptes personnels |
| **`pierre`** | `Pierre@1234` | **utilisateur (client)** | Consultation comptes personnels |

---

## ⚡ 7. Moteur Événementiel

Le cœur de XUD-Bank repose sur des événements publiés par les requêtes (ex: *tentative de connexion ratée*) et traités en arrière-plan :

```python
await dispatcher.emit("rate_limit", {
    "ip": "192.168.1.1",
    "username": "dupont",
    "count": 50
})
```

- **Non-bloquant** : Pas de blocage du Thread Serveur. L'utilisateur reçoit sa réponse instantanément, pendant que les modules d'analyse se lancent en parallèle.

---

## 🚨 8. Règles de Détection SOC

Le module Monitor écoute activement les évènements pour bloquer le trafic :

| Règle | Description | Déclencheur | Réaction | Alerte |
|---|---|---|---|---|
| **Règle 1** | Brute Force | 3 échecs sur un compte en < 2min | Verrouillage du compte (`is_locked`) | **MEDIUM** |
| **Règle 2** | Injection SQL | Patterns suspects: `' OR 1=1` | Rejet 400 immédiat | **HIGH** |
| **Règle 3** | Escalade de privilège | Requête `/admin/*` par un *client* | Révocation avec 403 | **HIGH** |
| **Règle 4** | Exfiltration | >20 requêtes de data en 1min | Flag de suspicion Massive | **CRITICAL** |
| **Règle 5** | Énumération | Une IP essaie différents pseudos | Fichage de l'IP | **MEDIUM** |
| **Règle 6** | Horaires atypiques | Connexion entre 20h00 et 07h00 | Inscription silencieuse | **LOW** |

---

## 🚀 9. Installation & Déploiement

### Prérequis

- Python 3.11+
- Base de données PostgreSQL fraîche (idéalement hébergée via Railway)

```bash
# 1. Cloner le repository
git clone https://github.com/votre-repo/xud-bank.git
cd xud-bank

# 2. Préparer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
.\venv\Scripts\activate   # Windows

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec DATABASE_URL (asyncpg) et SECRET_KEY

# 5. Initialiser la base de données
psql $DATABASE_URL < init_db.sql
psql $DATABASE_URL < seed_data.sql

# 6. Lancer l'application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

L'application est maintenant accessible sur `http://localhost:8000`.

---

## 📝 10. Journalisation

La sécurité s'accompagne toujours d'un bon logging :

1. **Fichiers Locaux** (`logs/security.log`) : Fichiers rotatifs limités à 5MB avec rotation de 3 backups. Évite la saturation du disque.
2. **Dashboard Temps Réel WebSocket** : Affichage graphique des détections sans réactualisation (flux réseau optimisé).
3. **Persistance en base de données** : Tables `security_events` et `alerts`.

---

## 🧪 11. Tests des Triggers d'Événements

Cette section détaille comment tester chaque règle de détection et déclencher manuellement les événements correspondants.

### Test 1 : Brute Force Login (Règle 1)

**Objectif** : Déclencher le verrouillage d'un compte après 3 échecs consécutifs.

**Procédure** :
```bash
# Effectuer 3 tentatives de connexion échouées en moins de 2 minutes
curl -X POST http://localhost:8000/login \
  -d "username=admin&password=WrongPassword1" \
  -c cookies.txt

curl -X POST http://localhost:8000/login \
  -d "username=admin&password=WrongPassword2" \
  -c cookies.txt

curl -X POST http://localhost:8000/login \
  -d "username=admin&password=WrongPassword3" \
  -c cookies.txt
```

**Résultat attendu** :
- ✅ Compte `admin` verrouillé (`is_locked = TRUE`)
- ✅ Événement `LOGIN_LOCKED` créé (severity: MEDIUM)
- ✅ Alerte MEDIUM générée
- ✅ Notification WebSocket envoyée au dashboard

**Vérification SQL** :
```sql
SELECT is_locked FROM users WHERE username = 'admin';
-- Doit retourner TRUE

SELECT * FROM security_events 
WHERE event_type = 'LOGIN_LOCKED' 
ORDER BY timestamp DESC LIMIT 1;

SELECT * FROM alerts 
WHERE alert_level = 'MEDIUM' 
ORDER BY timestamp DESC LIMIT 1;
```

---

### Test 2 : Injection SQL (Règle 2)

**Objectif** : Détecter et bloquer une tentative d'injection SQL.

**Procédure** :
```bash
# Tenter une injection SQL dans le formulaire de login
curl -X POST http://localhost:8000/login \
  -d "username=' OR 1=1 --&password=test" \
  -c cookies.txt

# Ou via l'URL
curl "http://localhost:8000/data/accounts?id=1' OR '1'='1"
```

**Résultat attendu** :
- ✅ Requête rejetée avec erreur 400
- ✅ Événement `SQL_INJECTION` créé (severity: HIGH)
- ✅ Alerte HIGH générée
- ✅ Payload enregistré dans les logs

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE event_type = 'SQL_INJECTION' 
ORDER BY timestamp DESC LIMIT 1;

SELECT * FROM alerts 
WHERE alert_level = 'HIGH' 
ORDER BY timestamp DESC LIMIT 1;
```

---

### Test 3 : Escalade de Privilège (Règle 3)

**Objectif** : Tenter d'accéder à une zone admin avec un rôle non autorisé.

**Procédure** :
```bash
# Se connecter avec un compte utilisateur standard
curl -X POST http://localhost:8000/login \
  -d "username=dupont&password=Dupont@1234" \
  -c cookies.txt

# Tenter d'accéder au dashboard admin
curl http://localhost:8000/admin/dashboard \
  -b cookies.txt
```

**Résultat attendu** :
- ✅ Accès refusé (403 Forbidden)
- ✅ Événement `UNAUTHORIZED_ACCESS` créé (severity: HIGH)
- ✅ Alerte HIGH générée
- ✅ Redirection vers page d'erreur

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE event_type = 'UNAUTHORIZED_ACCESS' 
  AND username = 'dupont'
ORDER BY timestamp DESC LIMIT 1;
```

---

### Test 4 : Exfiltration Massive (Règle 4)

**Objectif** : Déclencher l'alerte critique après plus de 20 accès aux données en 1 minute.

**Procédure** :
```bash
# Se connecter avec un compte utilisateur
curl -X POST http://localhost:8000/login \
  -d "username=dupont&password=Dupont@1234" \
  -c cookies.txt

# Effectuer 25 requêtes rapides vers les données sensibles
for i in {1..25}; do
  curl http://localhost:8000/data/accounts \
    -b cookies.txt &
done
wait
```

**Résultat attendu** :
- ✅ Alerte CRITICAL générée après le 20ème accès
- ✅ Événement `MASS_DATA_ACCESS` créé (severity: CRITICAL)
- ✅ Notification immédiate au SOC
- ✅ Utilisateur flaggé comme suspect

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE severity = 'CRITICAL' 
ORDER BY timestamp DESC LIMIT 1;

SELECT * FROM alerts 
WHERE alert_level = 'CRITICAL' 
ORDER BY timestamp DESC LIMIT 1;
```

---

### Test 5 : Énumération d'Utilisateurs (Règle 5)

**Objectif** : Détecter une IP testant plusieurs noms d'utilisateurs différents.

**Procédure** :
```bash
# Depuis la même IP, tenter 3 usernames différents en moins de 5 minutes
curl -X POST http://localhost:8000/login \
  -d "username=admin&password=wrong" \
  -c cookies.txt

curl -X POST http://localhost:8000/login \
  -d "username=soc&password=wrong" \
  -c cookies.txt

curl -X POST http://localhost:8000/login \
  -d "username=directeur&password=wrong" \
  -c cookies.txt
```

**Résultat attendu** :
- ✅ Événement `ENUM_ATTEMPT` créé (severity: MEDIUM)
- ✅ Alerte MEDIUM générée
- ✅ IP enregistrée comme suspecte
- ✅ Compteur d'IP distinctes跟踪é

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE event_type = 'ENUM_ATTEMPT' 
ORDER BY timestamp DESC LIMIT 1;

SELECT ip_address, COUNT(DISTINCT username_tried) as unique_users
FROM login_attempts
WHERE timestamp > NOW() - INTERVAL '5 minutes'
GROUP BY ip_address
HAVING COUNT(DISTINCT username_tried) >= 3;
```

---

### Test 6 : Accès Hors Horaires (Règle 6)

**Objectif** : Vérifier la détection des connexions en dehors des heures de bureau (20h-07h UTC).

**Procédure** :
```bash
# Modifier temporairement ALLOWED_HOURS_START/END dans .env
# Ou tester tard le soir / tôt le matin

curl -X POST http://localhost:8000/login \
  -d "username=pierre&password=Pierre@1234" \
  -c cookies.txt
```

**Résultat attendu** :
- ✅ Connexion réussie mais journalisée
- ✅ Événement `OFF_HOURS_ACCESS` créé (severity: LOW)
- ✅ Alerte LOW générée
- ✅ Heure de connexion enregistrée

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE event_type = 'OFF_HOURS_ACCESS' 
ORDER BY timestamp DESC LIMIT 1;

SELECT EXTRACT(HOUR FROM timestamp) as hour, username
FROM security_events
WHERE event_type = 'OFF_HOURS_ACCESS'
ORDER BY timestamp DESC;
```

---

### Test 7 : URL Suspecte / Path Traversal

**Objectif** : Détecter les tentatives d'accès à des fichiers sensibles.

**Procédure** :
```bash
# Tenter d'accéder à des fichiers système
curl "http://localhost:8000/../../../etc/passwd"
curl "http://localhost:8000/.env"
curl "http://localhost:8000/admin/../config.py"
```

**Résultat attendu** :
- ✅ Requête bloquée (403 Forbidden)
- ✅ Événement `SUSPICIOUS_URL` créé (severity: HIGH)
- ✅ Alerte HIGH générée
- ✅ URL suspecte enregistrée

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE event_type = 'SUSPICIOUS_URL' 
ORDER BY timestamp DESC LIMIT 1;
```

---

### Test 8 : Rate Limiting

**Objectif** : Déclencher la protection contre le flood de requêtes.

**Procédure** :
```bash
# Envoyer 50+ requêtes en moins d'une minute depuis la même IP
for i in {1..60}; do
  curl http://localhost:8000/data/accounts &
done
wait
```

**Résultat attendu** :
- ✅ Événement `RATE_LIMIT` créé (severity: MEDIUM)
- ✅ Alerte MEDIUM générée
- ✅ IP temporairement limitée
- ✅ Fenêtre temporelle enregistrée

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE event_type = 'RATE_LIMIT' 
ORDER BY timestamp DESC LIMIT 1;
```

---

## 📊 Monitoring des Tests

Pour suivre tous les événements en temps réel :

```sql
-- Voir les 10 derniers événements
SELECT event_type, severity, username, ip_address, description, timestamp
FROM security_events
ORDER BY timestamp DESC
LIMIT 10;

-- Voir les alertes non résolues
SELECT alert_level, message, timestamp
FROM alerts
WHERE resolved = FALSE
ORDER BY timestamp DESC;

-- Statistiques par type d'événement
SELECT event_type, COUNT(*) as count
FROM security_events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY event_type
ORDER BY count DESC;
```

---

> *Architecture réalisée par le département FAST-LPSIC M2 durant la session 2025-2026. L'outil reflète les standards défensifs Asynchrones modernes (Event-Loops, Threadpool GPU offloading, API sécurisée).*