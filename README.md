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
6. [Identification et Rôles (RBAC)](#-6-identification-et-rôles-rbac)
7. [Routes et Espaces Métiers](#-7-routes-et-espaces-métiers)
8. [Moteur Événementiel](#-8-moteur-événementiel)
9. [Règles de Détection SOC](#-9-règles-de-détection-soc)
10. [Rapports Bancaires](#-10-rapports-bancaires)
11. [Installation & Déploiement](#-11-installation--déploiement)
12. [Journalisation](#-12-journalisation)
13. [Tests des Triggers d'Événements](#-13-tests-des-triggers-dévénements)

---

## 🔍 1. Présentation

**XUD-Bank** est une application Web bancaire de démonstration destinée au personnel interne et aux clients. Elle intègre directement un moteur de détection d'intrusion appelé **SecureDataMonitor**. 

Le projet applique une **Séparation des Tâches (Segregation of Duties)** stricte : chaque métier dispose de son espace dédié avec des permissions spécifiques (Sécurité, Direction, Comptabilité, Client).

### Fonctionnalités Clés

- ✅ **Authentification sécurisée** avec sessions chiffrées
- ✅ **Contrôle d'accès basé sur les rôles (RBAC)**
- ✅ **Surveillance temps réel** via WebSockets
- ✅ **Détection automatique** de 7 règles de sécurité
- ✅ **Génération de rapports PDF** groupés par classification
- ✅ **Historique des transactions** stocké en JSON
- ✅ **Alertes CRITICAL** pour tentatives de vol de dossiers

---

## 🏗️ 2. Architecture

Le projet combine deux design patterns :

### Layered Architecture (4 couches)

```
┌─────────────────────────────────────────────┐
│  PRÉSENTATION  routers/ + templates/        │  HTTP, vues HTML, WebSocket (Espaces RBAC)
├─────────────────────────────────────────────┤
│  MÉTIER        services/auth_service.py     │  Logique bancaire, Threadpool, Bcrypt
├─────────────────────────────────────────────┤
│  ÉVÉNEMENTIELLE events/dispatcher.py        │  Pub/Sub, détection, alertes asynchrones
├─────────────────────────────────────────────┤
│  PERSISTANCE   models/ + database.py        │  CRUD SQLAlchemy 2.0 (asyncpg)
└─────────────────────────────────────────────┘
```

### Pattern Observer (Pub/Sub)

```
Router → dispatcher.emit() → Handler → Logger + Alert + WebSocket Broadcast
```

---

## 🛠️ 3. Stack Technologique

| Composant | Technologie | Détails |
|---|---|---|
| **Backend** | FastAPI (Python 3.13+) | Asynchrone natif, routers segmentés |
| **Base de données** | PostgreSQL (Railway) | Driver haute performance `asyncpg` |
| **ORM** | SQLAlchemy 2.0 | Opérations totalement asynchrones |
| **Mots de passe** | Passlib (Bcrypt cost=12) | Exécuté sur *Threadpool* (non-bloquant) |
| **Sessions** | itsdangerous | Cookies chiffrés et signés sans BDD |
| **WebSocket** | WebSockets natifs | Optimisation visuelle par Batching (`requestAnimationFrame`) |
| **PDF** | FPDF2 | Génération de rapports bancaires structurés |
| **Frontend** | HTML5 / Vanilla CSS / JS | Interfaces dynamiques / Chart.js / Google Fonts (Syne, Figtree) |

---

## 📁 4. Structure du Projet

```
xud-bank/
├── app/                              # Application Bancaire (Core)
│   ├── main.py                       # Point d'entrée, montage routers & middlewares
│   ├── database.py                   # Configuration Railway + Asyncpg
│   ├── config.py                     # Settings Pydantic + Jinja2 Environment
│   ├── models/                       # Schémas SQLAlchemy
│   │   ├── user.py                   # User, UserRole
│   │   ├── bank_account.py           # BankAccount, AccountClassification
│   │   ├── security_event.py         # SecurityEvent, EventType, SeverityLevel
│   │   ├── login_attempt.py          # LoginAttempt
│   │   └── alert.py                  # Alert
│   ├── routers/                      # Logique Role-Based Access Control
│   │   ├── auth.py                   # (/auth) Login, Logout, Register
│   │   ├── soc.py                    # (/soc/*) Surveillance, verrouillage comptes
│   │   ├── direction.py              # (/direction/*) Personnel, rapports, comptes
│   │   ├── comptabilite.py           # (/comptabilite/*) Gestion bancaire, création
│   │   └── client.py                 # (/client/*) Espace client, virements
│   ├── services/                     # Services métier
│   │   ├── auth_service.py           # Authentification, création users, RBAC
│   │   └── report_service.py         # Génération PDF legacy
│   ├── templates/                    # Front segmenté par rôle
│   │   ├── base.html                 # Template de base commun
│   │   ├── login.html                # Page de connexion
│   │   ├── register.html             # Page d'inscription (désactivée)
│   │   ├── errors/                   # Pages d'erreur (401, 403, 404, 500)
│   │   ├── soc/                      # Templates SOC (dashboard, alerts, events...)
│   │   ├── direction/                # Templates Direction (dashboard, accounts, rapport...)
│   │   ├── comptabilite/             # Templates Comptabilité (dashboard)
│   │   └── client/                   # Templates Client (dashboard)
│   └── static/css/                   # Styles CSS globaux
├── secureDataMonitor/                # SOC Engine (Composant de Surveillance)
│   ├── __init__.py
│   ├── events/                       # Système événementiel Pub/Sub
│   │   ├── dispatcher.py             # EventDispatcher central
│   │   └── handlers.py               # Handlers pour chaque type d'événement
│   ├── services/                     # Détection et journalisation
│   │   ├── detection.py              # 7 règles de détection
│   │   └── logger.py                 # Journalisation événements + alertes
│   ├── routers/                      # API REST & WebSockets
│   │   ├── api_alerts.py             # WebSocket broadcast + stats
│   │   └── admin.py                  # Routes admin legacy
│   ├── static/js/                    # Scripts JavaScript
│   │   └── ws_alerts.js              # Client WebSocket batching
│   └── templates/                    # Templates legacy (errors uniquement)
├── logs/                             # Fichiers de log locaux
│   └── security.log                  # Journal de sécurité
├── .cache/jinja2/                    # Cache bytecode Jinja2 (performance)
├── init_db.sql                       # Script initialisation BDD (schema + enums)
├── seed_data.sql                     # Données de démonstration
├── requirements.txt                  # Dépendances Python
├── .env                              # Variables d'environnement (gitignored)
├── env.example                       # Template .env
├── Procfile                          # Configuration déploiement
└── README.md                         # Ce fichier
```

---

## 💾 5. Modèle de Données

Le modèle repose sur PostgreSQL avec 5 tables principales :

### Tables Principales

#### **`users`** - Utilisateurs du système
- `id` (UUID) - Identifiant unique
- `username` (VARCHAR 50) - Nom d'utilisateur (unique)
- `email` (VARCHAR 100) - Email (unique)
- `password_hash` (VARCHAR 255) - Hash bcrypt
- `role` (ENUM: soc, directeur, comptable, utilisateur)
- `is_locked` (BOOLEAN) - Statut de verrouillage
- `failed_attempts` (INTEGER) - Compteur d'échecs
- `last_failed_at` (TIMESTAMP) - Dernier échec
- `created_at` (TIMESTAMP) - Date de création

#### **`bank_accounts`** - Comptes bancaires
- `id` (UUID) - Identifiant unique
- `id_compte` (VARCHAR 20) - Numéro de compte (unique)
- `titulaire` (VARCHAR 100) - Nom du titulaire
- `solde` (DECIMAL 15,2) - Solde actuel
- `historique` (TEXT) - **JSON sérialisé des transactions**
- `classification` (ENUM: public, confidentiel, secret)
- `owner_id` (UUID FK → users.id) - Propriétaire du compte
- `created_at` (TIMESTAMP) - Date de création

#### **`security_events`** - Journal de sécurité
- `id` (UUID) - Identifiant unique
- `timestamp` (TIMESTAMP) - Horodatage
- `username` (VARCHAR 50) - Utilisateur concerné
- `ip_address` (INET) - Adresse IP
- `event_type` (ENUM: 13 types dont BANK_FRAUD_ATTEMPT)
- `severity` (ENUM: LOW, MEDIUM, HIGH, CRITICAL)
- `description` (TEXT) - Description détaillée
- `status` (ENUM: open, investigating, closed)
- `action_taken` (TEXT) - Action entreprise

#### **`alerts`** - Alertes générées
- `id` (UUID) - Identifiant unique
- `timestamp` (TIMESTAMP) - Horodatage
- `alert_level` (ENUM: LOW, MEDIUM, HIGH, CRITICAL)
- `source_event_id` (UUID FK → security_events.id)
- `message` (TEXT) - Message d'alerte
- `resolved` (BOOLEAN) - Statut de résolution

#### **`login_attempts`** - Tentatives de connexion
- `id` (UUID) - Identifiant unique
- `ip_address` (INET) - Adresse IP source
- `username_tried` (VARCHAR 50) - Username essayé
- `timestamp` (TIMESTAMP) - Horodatage
- `success` (BOOLEAN) - Succès ou échec

### Index Performance

- `idx_login_attempts_username_time` - Détection brute force
- `idx_login_attempts_ip_time` - Détection énumération
- `idx_security_events_type`, `idx_security_events_severity` - Filtrage dashboard
- `idx_alerts_unresolved` - Alertes actives
- `idx_bank_accounts_owner` - Accès rapide par propriétaire

---

## 👥 6. Identification et Rôles (RBAC)

L'inscription publique est **désactivée**. Les comptes sont créés exclusivement par la **Direction**.

| Username | Role | Espace Dédié | Privilèges & Responsabilités |
|---|---|---|---|
| **`soc`** | `soc` | `/soc/*` | Surveillance temps réel, **Verrouillage des comptes**, Logs bruts, Clear data, Alerts, Events |
| **`directeur`** | `directeur` | `/direction/*` | **Recrutement/Radiation personnel**, **Rapports complets** (PUBLIC+CONFIDENTIEL+SECRET), Gestion comptes bancaires |
| **`hor`** | `comptable` | `/comptabilite/*` | **Création de comptes bancaires**, **Rapports** (PUBLIC+CONFIDENTIEL), Gestion virements |
| **`dupont`** | `utilisateur` | `/client/*` | Consultation soldes, **Virements personnels**, Historique transactions |

### Matrice d'Accès aux Rapports

| Rôle | `/direction/rapport` | `/comptabilite/rapport` |
|------|---------------------|------------------------|
| directeur | ✅ AUTORISÉ | ✅ AUTORISÉ |
| comptable | ❌ INTERDIT → **CRITICAL** | ✅ AUTORISÉ |
| soc | ❌ INTERDIT → **CRITICAL** | ❌ INTERDIT → **CRITICAL** |
| utilisateur | ❌ INTERDIT → **CRITICAL** | ❌ INTERDIT → **CRITICAL** |

---

## 🛣️ 7. Routes et Espaces Métiers

### **Espace Authentification** (`/auth`)
- `GET /auth/login` - Page de connexion
- `POST /auth/login` - Traitement login
- `GET /auth/logout` - Déconnexion
- `GET /auth/register` - Inscription (désactivée)
- `POST /auth/register` - Création compte (désactivée)

### **Espace SOC** (`/soc`)
- `GET /soc/dashboard` - Dashboard sécurité temps réel (WebSockets)
- `GET /soc/users` - Liste utilisateurs avec actions verrouillage/déverrouillage
- `GET /soc/alerts` - Gestion des alertes (actives/résolues)
- `GET /soc/events` - Historique événements de sécurité
- `GET /soc/logs/raw` - Affichage brut du fichier security.log
- `GET /soc/clear-data` - Page suppression données (confirmations)
- `POST /soc/clear-data` - Suppression effective alerts + events
- `POST /soc/alerts/{id}/resolve` - Résolution manuelle d'alerte
- `POST /soc/users/{id}/lock` - Verrouillage compte utilisateur
- `POST /soc/users/{id}/unlock` - Déverrouillage compte utilisateur

### **Espace Direction** (`/direction`)
- `GET /direction/dashboard` - Dashboard direction (stats sécurité)
- `GET /direction/users` - Gestion personnel (SOC, directeurs, comptables)
- `GET /direction/users/new` - Formulaire recrutement
- `POST /direction/users/new` - Création nouveau personnel
- `POST /direction/users/{id}/delete` - Radiation personnel
- `GET /direction/accounts` - **Vision complète des comptes** (PUBLIC+CONFIDENTIEL+SECRET)
- `GET /direction/rapport` - **Rapport PDF détaillé** tous comptes avec horodatages

### **Espace Comptabilité** (`/comptabilite`)
- `GET /comptabilite/dashboard` - Dashboard gestion bancaire
- `POST /comptabilite/accounts/create` - Création nouveau compte bancaire
- `GET /comptabilite/rapport` - **Rapport PDF** comptes PUBLIC+CONFIDENTIEL uniquement

### **Espace Client** (`/client`)
- `GET /client/dashboard` - Dashboard client personnel
- `POST /client/transfers` - Effectuer un virement
- `GET /client/history` - Historique transactions personnelles

### **WebSocket**
- `WS /ws/alerts` - Connexion temps réel pour alertes SOC

### **Health Check**
- `GET /health` - Vérification statut BDD
- `GET /` - Redirection vers `/auth/login`

---

## ⚡ 8. Moteur Événementiel

Le système utilise un **Dispatcher asynchrone** (pattern Pub/Sub) pour traiter les menaces sans ralentir l'utilisateur :

### Architecture Événementielle

```python
# 1. Un router émet un événement
await dispatcher.emit("bank_fraud_attempt", {
    "ip": "192.168.1.100",
    "username": "jean_comptable",
    "role": "comptable",
    "path": "/direction/rapport"
})

# 2. Le dispatcher appelle tous les handlers abonnés
# 3. Chaque handler exécute en parallèle :
#    - Journalisation dans security_events
#    - Création d'alerte si nécessaire
#    - Broadcast WebSocket aux dashboards
#    - Actions automatiques (verrouillage, etc.)
```

### Types d'Événements Supportés

| Événement | Déclencheur | Handler | Sévérité |
|-----------|-------------|---------|----------|
| `login_success` | Connexion réussie | `handle_login_success` | LOW |
| `login_failed` | Échec connexion | `handle_failed_login` | MEDIUM |
| `account_locked` | Compte verrouillé | `handle_account_locked` | MEDIUM |
| `unknown_user` | Utilisateur inconnu | `handle_unknown_user` | MEDIUM |
| `unauthorized` | Accès non autorisé | `handle_unauthorized` | HIGH |
| `privilege_escalation` | Escalade privilèges | `handle_privilege_escalation` | HIGH |
| `rate_limit` | Rate limiting | `handle_rate_limit` | MEDIUM |
| `mass_data_access` | Exfiltration massive | `handle_mass_access` | CRITICAL |
| `off_hours_access` | Accès hors horaires | `handle_off_hours` | LOW |
| `sql_injection` | Injection SQL détectée | `handle_sql_injection` | HIGH |
| `enum_attempt` | Énumération usernames | `handle_enum_attempt` | MEDIUM |
| `suspicious_url` | URL suspecte | `handle_suspicious_url` | HIGH |
| **`bank_fraud_attempt`** | **Vol dossiers bancaires** | **`handle_bank_fraud_attempt`** | **CRITICAL** |

---

## 🚨 9. Règles de Détection SOC

Le moteur Monitor écoute et réagit selon **7 politiques de sécurité** :

| Règle | Nom | Description | Déclencheur | Réaction | Alerte |
|-------|-----|-------------|-------------|----------|--------|
| **Règle 1** | Brute Force | 3 échecs en < 2min | `check_brute_force()` | Verrouillage automatique compte | **MEDIUM** |
| **Règle 2** | Injection SQL | Patterns `' OR 1=1`, `UNION SELECT`, `; DROP` | `check_sql_injection()` | Rejet 400 immédiat + Log payload | **HIGH** |
| **Règle 3** | Accès Illégitime | Client tentant `/soc/*` ou `/admin/*` | `check_admin_access()` | Permission Denied (403) | **HIGH** |
| **Règle 4** | Exfiltration Masse | >20 accès données en < 1min | `record_data_access()` | Signalement suspicion exfiltration | **CRITICAL** |
| **Règle 5** | Énumération | 3 usernames différents depuis IP < 5min | `check_enumeration()` | Fichage et surveillance IP | **MEDIUM** |
| **Règle 6** | Off-Hours | Connexion entre 20h00 et 07h00 UTC | `check_off_hours()` | Inscription discrète événement | **LOW** |
| **Règle 7** | **Vol Dossiers** | **Accès non autorisé aux rapports bancaires** | **`check_unauthorized_report_access()`** | **Accès refusé + Alerte immédiate** | **🔴 CRITICAL** |

### Détail Règle 7 - Vol de Dossiers Bancaires

**Routes protégées :**
- `/direction/rapport` → Réservé au **directeur** uniquement
- `/comptabilite/rapport` → Réservé au **comptable** et **directeur**

**Actions déclenchées :**
1. Journalisation événement `BANK_FRAUD_ATTEMPT` (sévérité CRITICAL)
2. Création alerte CRITICAL avec message explicite
3. Broadcast WebSocket temps réel aux dashboards SOC
4. Log critique dans `security.log`

**Exemple d'alerte :**
```
🚨⚠️ VOL DE DOSSIERS BANCAIRES : Utilisateur 'jean_comptable' (rôle: comptable) 
a tenté d'accéder à /direction/rapport depuis 192.168.1.100 - NIVEAU CRITIQUE
```

---

## 📄 10. Rapports Bancaires

Le système génère des **rapports PDF structurés** groupés par classification de sécurité.

### Rapport Direction (`/direction/rapport`)

**Accès :** Directeur uniquement  
**Contenu :** TOUS les comptes (PUBLIC + CONFIDENTIEL + SECRET)

**Structure du PDF :**
```
┌─────────────────────────────────────────┐
│  XUD-BANK - RAPPORT DETAILLE DES COMPTES│
│  Généré le 03/04/2026 à 14:30           │
│  Par: directeur (Directeur)             │
│  Accès: PUBLIC + CONFIDENTIEL + SECRET  │
├─────────────────────────────────────────┤
│  STATISTIQUES GLOBALES                  │
│  Total Global: 1,250,000.00 XOF         │
│  PUBLIC: 5 comptes | CONFIDENTIEL: 8    │
│  SECRET: 3 comptes                      │
├─────────────────────────────────────────┤
│  [PUBLIC] COMPTES PUBLIC                │
│  Sous-total: 250,000.00 XOF (5 comptes) │
│  ┌──────────┬──────────┬──────────┐    │
│  │ ID       │Titulaire │ Solde    │    │
│  ├──────────┼──────────┼──────────┤    │
│  │ FR76...  │ Dupont   │ 50,000   │    │
│  └──────────┴──────────┴──────────┘    │
├─────────────────────────────────────────┤
│  [CONFIDENTIEL] COMPTES CONFIDENTIEL    │
│  ...                                    │
├─────────────────────────────────────────┤
│  [SECRET] COMPTES SECRET                │
│  ...                                    │
└─────────────────────────────────────────┘
```

### Rapport Comptabilité (`/comptabilite/rapport`)

**Accès :** Comptable et Directeur  
**Contenu :** Seulement PUBLIC + CONFIDENTIEL (pas de SECRET)

**Différences avec rapport Direction :**
- Pas de section SECRET
- Mention "Accès : PUBLIC + CONFIDENTIEL"
- Titre "RAPPORT DES COMPTES - COMPTABILITE"

### Caractéristiques Communes

✅ **Ouverture directe** dans le navigateur (`Content-Disposition: inline`)  
✅ **Groupement par classification** avec codes couleur  
✅ **Horodatages complets** (date création, dernière MAJ)  
✅ **Statistiques détaillées** (sous-totaux par section)  
✅ **Pagination automatique** pour longs rapports  
✅ **Nom de fichier horodaté** : `rapport_YYYYMMDD_HHMM.pdf`  

---

## 🚀 11. Installation & Déploiement

### Prérequis

- Python 3.11+
- PostgreSQL (local ou Railway)
- pip (gestionnaire de paquets Python)

### Initialisation

```bash
# 1. Cloner le repository
git clone <repository-url>
cd xud-bank

# 2. Créer environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# 3. Installer dépendances
pip install -r requirements.txt

# 4. Configurer variables d'environnement
cp env.example .env
# Éditer .env avec vos credentials BDD
nano .env

# 5. Initialiser base de données (remise à zéro complète)
psql $DATABASE_URL < init_db.sql
psql $DATABASE_URL < seed_data.sql

# 6. Lancer serveur développement
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Variables d'Environnement (.env)

```env
# Base de données
DATABASE_URL=postgresql+asyncpg://user:pass@host:port/dbname

# Sécurité sessions
SECRET_KEY=votre_cle_secrete_tres_longue_et_aleatoire

# Configuration détection
BRUTE_FORCE_WINDOW=120
MAX_LOGIN_ATTEMPTS=3
MASS_ACCESS_WINDOW=60
MASS_ACCESS_LIMIT=20
ENUM_WINDOW=300
ENUM_USERNAMES_LIMIT=3
ALLOWED_HOURS_START=7
ALLOWED_HOURS_END=20

# Logging
LOG_FILE_PATH=logs/security.log
```

### Déploiement Production

```bash
# Utiliser Gunicorn avec workers uvicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

# Ou via Procfile (Heroku/Railway)
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

---

## 📝 12. Journalisation

La sécurité s'accompagne d'une visibilité totale sur 3 niveaux :

### 1. Fichiers Locaux
- **Emplacement :** `logs/security.log`
- **Format :** Texte structuré avec timestamps
- **Usage :** Analyses judiciaires, audit post-mortem
- **Rotation :** À configurer selon politique entreprise

### 2. Dashboard Temps Réel
- **URL :** `/soc/dashboard`
- **Technologie :** WebSockets avec batching `requestAnimationFrame`
- **Fonctionnalités :**
  - Graphiques fréquence événements (Chart.js)
  - Stats par sévérité (LOW/MEDIUM/HIGH/CRITICAL)
  - Top IPs suspectes
  - Alertes en temps réel
  - Liste derniers événements

### 3. Persistance Base de Données
- **Table `security_events`** : Historique indélébile de tous les incidents
- **Table `alerts`** : Notifications levées avec statut résolution
- **Requêtes optimisées** : Index sur timestamp, severity, event_type
- **Cache 5 secondes** : Dashboard stats avec TTL pour performance

### Niveaux de Sévérité

| Niveau | Couleur | Usage | Exemple |
|--------|---------|-------|---------|
| **LOW** | 🟢 Vert | Information normale | Connexion réussie, accès hors horaires |
| **MEDIUM** | 🟡 Jaune | Attention requise | Échec connexion ×3, énumération |
| **HIGH** | 🟠 Orange | Danger détecté | Injection SQL, accès non autorisé |
| **CRITICAL** | 🔴 Rouge | Urgence absolue | Exfiltration massive, **vol dossiers** |

---

## 🧪 13. Tests des Triggers d'Événements

### Test 1 : Escalade de Privilège (Règle 3)

**Objectif :** Vérifier que les rôles sont étanches

```bash
# Se connecter en tant que client (dupont)
curl -X POST http://localhost:8000/auth/login \
  -d "email=dupont@mail.com&password=Dupont@1234" \
  -c cookies.txt

# Tenter d'accéder à la console SOC
curl http://localhost:8000/soc/users -b cookies.txt

# Tenter d'accéder au rapport direction
curl http://localhost:8000/direction/rapport -b cookies.txt
```

**Résultat attendu :** 
- Code 403 Forbidden
- Alerte **CRITICAL** dans `/soc/dashboard`
- Message : "🚨⚠️ VOL DE DOSSIERS BANCAIRES"

---

### Test 2 : Verrouillage SOC (Règle 1)

**Objectif :** Simuler attaque brute-force

```bash
for i in {1..4}; do
  curl -X POST http://localhost:8000/auth/login \
    -d "email=directeur@xud-bank.com&password=FauxPassword"
done
```

**Résultat attendu :**
- Après 3 essais : compte devient `is_locked = TRUE`
- Alerte MEDIUM créée
- SOC peut déverrouiller via `/soc/users`

---

### Test 3 : Injection SQL (Règle 2)

**Objectif :** Tester détection patterns SQL

```bash
# Tentative injection dans login
curl -X POST http://localhost:8000/auth/login \
  -d "email=admin' OR '1'='1&password=test"

# Tentative UNION injection
curl "http://localhost:8000/client/dashboard?id=1 UNION SELECT * FROM users"
```

**Résultat attendu :**
- Rejet immédiat (400 Bad Request)
- Alerte HIGH dans dashboard
- Payload SQL journalisé

---

### Test 4 : Vol Dossiers Bancaires (Règle 7)

**Objectif :** Vérifier protection rapports sensibles

```bash
# Se connecter en tant que comptable
curl -X POST http://localhost:8000/auth/login \
  -d "email=hor@xud-bank.com&password=Hor@1234" \
  -c cookies_comptable.txt

# Tenter d'accéder au rapport direction (interdit)
curl http://localhost:8000/direction/rapport -b cookies_comptable.txt
```

**Résultat attendu :**
- Code 403 Forbidden
- Alerte **CRITICAL** immédiate
- Message : "🚨⚠️ VOL DE DOSSIERS BANCAIRES : Utilisateur 'hor' (rôle: comptable) a tenté d'accéder à /direction/rapport"
- Apparition en temps réel sur dashboard SOC

---

### Test 5 : Exfiltration Massive (Règle 4)

**Objectif :** Simuler consultation excessive de données

```python
import requests

session = requests.Session()
# Login d'abord
session.post("http://localhost:8000/auth/login", 
             data={"email": "hor@xud-bank.com", "password": "Hor@1234"})

# Consulter dashboard comptabilité 25 fois rapidement
for i in range(25):
    session.get("http://localhost:8000/comptabilite/dashboard")
```

**Résultat attendu :**
- Après 20 consultations en < 1min : alerte CRITICAL
- Événement `MASS_DATA_ACCESS` créé
- Notification SOC temps réel

---

### Test 6 : Génération Rapports PDF

**Objectif :** Vérifier génération rapports structurés

```bash
# Se connecter en directeur
curl -X POST http://localhost:8000/auth/login \
  -d "email=directeur@xud-bank.com&password=Directeur@1234" \
  -c cookies_directeur.txt

# Télécharger rapport complet
curl http://localhost:8000/direction/rapport \
  -b cookies_directeur.txt \
  -o rapport_direction.pdf

# Ouvrir dans navigateur
xdg-open rapport_direction.pdf  # Linux
open rapport_direction.pdf      # Mac
start rapport_direction.pdf     # Windows
```

**Résultat attendu :**
- PDF bien formaté avec sections colorées
- Groupement PUBLIC / CONFIDENTIEL / SECRET
- Statistiques globales correctes
- Horodatages complets

---

## 🎯 Bonnes Pratiques de Sécurité

### Pour les Développeurs

1. **Ne jamais commit `.env`** - Contient secrets et credentials
2. **Utiliser `require_role()`** - Toujours protéger routes sensibles
3. **Logger les accès critiques** - Toutes les actions importantes doivent être tracées
4. **Valider inputs** - Tous les paramètres utilisateur doivent être validés
5. **HTTPS en production** - Jamais de sessions en clair

### Pour les Administrateurs SOC

1. **Surveiller alertes CRITICAL** - Réponse immédiate requise
2. **Vérifier logs quotidiennement** - Détection proactive
3. **Auditer accès rapports** - Qui consulte quoi et quand
4. **Rotation mots de passe** - Politique stricte pour comptes privilégiés
5. **Backup régulier BDD** - Inclure security_events pour audit

### Pour les Utilisateurs

1. **Mots de passe forts** - Minimum 12 caractères, mixte
2. **Ne pas partager credentials** - Chaque utilisateur a son propre compte
3. **Signaler activités suspectes** - Contacter SOC immédiatement
4. **Déconnexion systématique** - Sur postes partagés
5. **Vérifier URLs** - Phishing possible

---

## 📊 Métriques et Monitoring

### Indicateurs Clés (KPIs)

- **Temps moyen réponse alertes CRITICAL** : Objectif < 5 minutes
- **Nombre tentatives intrusion/jour** : Surveillance tendance
- **Taux faux positifs** : Ajustement règles si > 10%
- **Disponibilité système** : Objectif 99.9% uptime
- **Temps génération rapports** : Objectif < 3 secondes

### Dashboard SOC

Le dashboard `/soc/dashboard` fournit en temps réel :
- Graphique fréquence événements (24h glissantes)
- Répartition par sévérité (camembert)
- Top 5 IPs suspectes
- Dernières 10 alertes non résolues
- Derniers 10 événements de sécurité
- Compteurs globaux (events, alerts, locked accounts)

---

## 🔮 Évolutions Futures

### Court Terme
- [ ] Authentification 2FA (TOTP)
- [ ] Export CSV transactions
- [ ] Recherche avancée dans historiques
- [ ] Notifications email alertes CRITICAL
- [ ] Rate limiting par IP

### Moyen Terme
- [ ] Machine Learning détection anomalies
- [ ] API REST externe pour partenaires
- [ ] Audit trail complet (qui a fait quoi)
- [ ] Chiffrement historique transactions
- [ ] Multi-factor authentication obligatoire SOC

### Long Terme
- [ ] Microservices architecture
- [ ] Blockchain pour immutabilité logs
- [ ] Intelligence artificielle prédictive
- [ ] Compliance RGPD automatisée
- [ ] Disaster recovery site

---

## 👨‍💻 Contributeurs

**Projet réalisé par l'équipe FAST-LPSIC M2**  
Université de Kara - Session 2025-2026

### Technologies Maîtrisées
- Architecture événementielle asynchrone
- Contrôle d'accès granulaire (RBAC)
- Détection intrusion temps réel
- Génération documents professionnels
- WebSockets haute performance
- Sécurité défense en profondeur

---

## 📄 Licence

Ce projet est développé dans un cadre académique. Toute utilisation commerciale doit faire l'objet d'une autorisation préalable.

---

> **Note importante :** Cette application est une démonstration pédagogique. En production, des mesures de sécurité supplémentaires seraient nécessaires (WAF, IDS/IPS, chiffrement end-to-end, audit externe, etc.).

**Pour toute question ou support technique, contacter l'équipe de développement.**
