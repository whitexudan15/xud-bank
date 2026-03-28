# XUD-Bank — SecureDataMonitor

> Application Web bancaire sécurisée avec moteur de surveillance événementielle en temps réel.  
> Université de Kara – FAST-LPSIC S6 | Programmation Événementielle & Cybersécurité | 2025-2026

---

## Table des matières

1. [Présentation](#1-présentation)
2. [Architecture](#2-architecture)
3. [Stack technologique](#3-stack-technologique)
4. [Structure du projet](#4-structure-du-projet)
5. [Modèle de données](#5-modèle-de-données)
6. [Logique événementielle](#6-logique-événementielle)
7. [Règles de détection](#7-règles-de-détection)
8. [Interfaces & Rôles](#8-interfaces--rôles)
9. [Installation](#9-installation)
10. [Configuration](#10-configuration)
11. [Identifiants de test](#11-identifiants-de-test)
12. [Scénarios de test](#12-scénarios-de-test)
13. [Journalisation](#13-journalisation)

---

## 1. Présentation

**XUD-Bank** est une application Web bancaire simulée destinée au personnel interne et aux clients bancaires. Elle est couplée au moteur **SecureDataMonitor** qui surveille, détecte et alerte en temps réel sur toute activité suspecte.

### Objectifs

- Fournir une interface bancaire avec authentification et gestion de rôles
- Implémenter un moteur de surveillance événementielle (Pub/Sub)
- Détecter au moins 5 types d'attaques
- Générer des alertes sur 4 niveaux de gravité (LOW, MEDIUM, HIGH, CRITICAL)
- Journaliser toutes les actions en fichier et en base de données
- Produire un tableau de bord sécurité en temps réel via WebSocket

---

## 2. Architecture

Le projet suit deux design patterns combinés :

### Layered Architecture (4 couches strictes)

```
┌─────────────────────────────────────────────┐
│  PRÉSENTATION  routers/ + templates/         │  HTTP, rendu HTML, sessions
├─────────────────────────────────────────────┤
│  MÉTIER        services/auth_service.py      │  Logique bancaire pure
├─────────────────────────────────────────────┤
│  ÉVÉNEMENTIELLE events/dispatcher.py         │  Pub/Sub, détection, alertes
├─────────────────────────────────────────────┤
│  PERSISTANCE   models/ + database.py         │  CRUD SQLAlchemy async
└─────────────────────────────────────────────┘
```

### Event-Driven Pattern (Pub/Sub)

```
Router (app bancaire)
    │
    │  dispatcher.emit("login_failed", {...})
    ▼
EventDispatcher
    │
    ├──▶ handle_failed_login()  ──▶  detection.check_brute_force()
    │                                logger.log_event()
    │                                logger.create_alert()  ──▶  WebSocket broadcast
    │
    └──▶ [autres handlers abonnés]
```

Zéro couplage entre l'application bancaire et le moteur de surveillance.

---

## 3. Stack technologique

| Couche | Technologie | Justification |
|---|---|---|
| Backend | FastAPI (Python 3.11+) | async/await natif, WebSocket intégré |
| Base de données | PostgreSQL via Supabase | Hébergé, SSL, scalable |
| ORM | SQLAlchemy 2.x async + asyncpg | Driver async PostgreSQL le plus performant |
| Templating | Jinja2 | Rendu server-side, auto-escape XSS |
| Frontend | Bootstrap 5 + JS vanilla | Léger, sans build step |
| Alertes temps réel | WebSocket (FastAPI natif) | Push instantané, zéro latence |
| Sessions | itsdangerous (cookie signé) | Sans état côté serveur |
| Mots de passe | passlib[bcrypt] cost=12 | Standard sécurité moderne |
| Logs fichier | logging.RotatingFileHandler | Rotation automatique 5MB × 3 |
| Déploiement | Render.com + Supabase | Gratuit pour démo |

---

## 4. Structure du projet

```
xud-bank/
├── app/                              # Application Web bancaire
│   ├── main.py                       # Point d'entrée FastAPI + lifespan + middleware
│   ├── config.py                     # Settings Pydantic (chargés depuis .env)
│   ├── database.py                   # Engine async SQLAlchemy, session factory
│   ├── models/
│   │   ├── user.py                   # Table users
│   │   ├── bank_account.py           # Table bank_accounts (données sensibles)
│   │   ├── security_event.py         # Table security_events + ENUMs
│   │   ├── alert.py                  # Table alerts
│   │   └── login_attempt.py          # Table login_attempts (tracking)
│   ├── routers/
│   │   ├── auth.py                   # Login, logout, register
│   │   └── data.py                   # Consultation comptes bancaires
│   ├── services/
│   │   └── auth_service.py           # bcrypt, sessions, authenticate(), require_role()
│   └── templates/
│       ├── base.html                 # Layout global Bootstrap
│       ├── login.html                # Page connexion
│       ├── register.html             # Inscription client
│       └── data.html                 # Vue comptes bancaires
│
├── secureDataMonitor/                # Moteur de surveillance événementielle
│   ├── events/
│   │   ├── dispatcher.py             # EventDispatcher (emit/subscribe) — Pub/Sub
│   │   └── handlers.py               # 12 handlers + register_all_handlers()
│   ├── services/
│   │   ├── detection.py              # 6 règles de détection
│   │   └── logger.py                 # Double journalisation fichier + BDD
│   ├── routers/
│   │   ├── admin.py                  # Dashboard, users, events, alerts
│   │   └── api_alerts.py             # WebSocket + REST API
│   ├── templates/
│   │   ├── dashboard.html            # Tableau de bord sécurité temps réel
│   │   ├── admin/
│   │   │   ├── index.html            # Vue synthèse admin
│   │   │   ├── users.html            # Gestion utilisateurs + verrouillage
│   │   │   ├── events.html           # Historique security_events filtrable
│   │   │   └── alerts.html           # Gestion alertes + résolution
│   │   └── errors/
│   │       ├── 403.html
│   │       └── 404.html
│   └── static/
│       └── js/ws_alerts.js           # Client WebSocket avec reconnexion auto
│
├── docs/
│   └── XUD-Bank_Architecture.docx    # Document d'architecture complet
├── logs/
│   └── security.log                  # Logs rotatifs (5MB × 3)
├── init_db.sql                       # Script création tables PostgreSQL
├── seed_data.sql                     # Données de test avec vrais hash bcrypt
├── requirements.txt
└── .env.example                      # Template de configuration
```

---

## 5. Modèle de données

### Table `users`

| Colonne | Type | Description |
|---|---|---|
| `id` | UUID PK | Identifiant unique |
| `username` | VARCHAR(50) UNIQUE | Nom d'utilisateur |
| `email` | VARCHAR(100) UNIQUE | Email |
| `password_hash` | VARCHAR(255) | Hash bcrypt cost=12 |
| `role` | ENUM | `admin` \| `analyste` \| `utilisateur` |
| `is_locked` | BOOLEAN | Compte verrouillé après brute force |
| `failed_attempts` | INTEGER | Compteur d'échecs consécutifs |
| `last_failed_at` | TIMESTAMP | Dernier échec (fenêtre Règle 1) |
| `created_at` | TIMESTAMP | Date de création |

### Table `bank_accounts` (données sensibles)

| Colonne | Type | Description |
|---|---|---|
| `id` | UUID PK | Identifiant unique |
| `id_compte` | VARCHAR(20) UNIQUE | Numéro de compte |
| `titulaire` | VARCHAR(100) | Nom du titulaire |
| `solde` | DECIMAL(15,2) | Solde actuel |
| `historique` | TEXT | Transactions (JSON sérialisé) |
| `classification` | ENUM | `public` \| `confidentiel` \| `secret` |
| `owner_id` | UUID FK | Propriétaire (→ users) |

### Table `security_events` (journal central)

| Colonne | Type | Description |
|---|---|---|
| `id` | UUID PK | Identifiant unique |
| `timestamp` | TIMESTAMP | Date/heure UTC |
| `username` | VARCHAR | Utilisateur impliqué (NULL si inconnu) |
| `ip_address` | INET | IP source |
| `event_type` | ENUM | 12 types d'événements |
| `severity` | ENUM | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `description` | TEXT | Détail complet |
| `status` | ENUM | `open` \| `investigating` \| `closed` |
| `action_taken` | TEXT | Action automatique déclenchée |

### Table `alerts`

| Colonne | Type | Description |
|---|---|---|
| `id` | UUID PK | Identifiant unique |
| `timestamp` | TIMESTAMP | Date/heure UTC |
| `alert_level` | ENUM | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` |
| `source_event_id` | UUID FK | Événement déclencheur |
| `message` | TEXT | Message descriptif |
| `resolved` | BOOLEAN | Résolue par SOC/admin |

### Table `login_attempts`

| Colonne | Type | Description |
|---|---|---|
| `id` | UUID PK | Identifiant unique |
| `ip_address` | INET | IP source |
| `username_tried` | VARCHAR(50) | Username tenté |
| `timestamp` | TIMESTAMP | Moment de la tentative |
| `success` | BOOLEAN | Succès ou échec |

---

## 6. Logique événementielle

### EventDispatcher

```python
# Abonnement
dispatcher.subscribe("login_failed", handle_failed_login)

# Émission depuis un router
await dispatcher.emit("login_failed", {
    "username": "jdoe",
    "ip": "192.168.1.1",
    "attempt": 2,
})
```

Handlers exécutés en **concurrence** via `asyncio.gather()`.

### 12 événements catalogués

| Événement | Handler | Severity |
|---|---|---|
| `login_success` | `handle_login_success` | LOW |
| `login_failed` | `handle_failed_login` | MEDIUM |
| `account_locked` | `handle_account_locked` | MEDIUM |
| `unknown_user` | `handle_unknown_user` | MEDIUM |
| `unauthorized` | `handle_unauthorized` | HIGH |
| `privilege_escalation` | `handle_privilege_escalation` | HIGH |
| `sql_injection` | `handle_sql_injection` | HIGH |
| `rate_limit` | `handle_rate_limit` | MEDIUM |
| `mass_data_access` | `handle_mass_access` | CRITICAL |
| `enum_attempt` | `handle_enum_attempt` | MEDIUM |
| `off_hours_access` | `handle_off_hours` | LOW |
| `suspicious_url` | `handle_suspicious_url` | HIGH |

### Flux login échoué

```
POST /auth/login → authenticate() → ÉCHEC
    │
    ▼
dispatcher.emit("login_failed", {username, ip, attempt})
    │
    ▼
handle_failed_login()
    ├── record_login_attempt()       → BDD
    ├── check_brute_force()          → Règle 1 ?
    ├── log_event(LOGIN_FAILED)      → BDD + fichier
    └── [si Règle 1] :
        ├── lock_account()           → is_locked = TRUE
        ├── create_alert(MEDIUM)     → BDD + fichier
        └── emit("account_locked")   → handler secondaire
```

---

## 7. Règles de détection

| # | Règle | Condition | Action | Alerte |
|---|---|---|---|---|
| 1 | Brute Force | 3 échecs < 2 min (même username) | Verrouillage compte | MEDIUM |
| 2 | SQL Injection | Pattern SQLi dans les inputs | Rejet requête | HIGH |
| 3 | Accès Admin | Rôle insuffisant → `/admin/*` | Redirection 403 | HIGH |
| 4 | Exfiltration | >20 consultations < 1 min | Notification immédiate | CRITICAL |
| 5 | Énumération | Même IP → 3 usernames < 5 min | IP signalée | MEDIUM |
| 6 | Hors horaires | Connexion hors 07h–20h UTC | Log uniquement | LOW |

---

## 8. Interfaces & Rôles

| Route | Accès | Description |
|---|---|---|
| `/auth/login` | Public | Connexion |
| `/auth/register` | Public | Inscription |
| `/data/accounts` | Tous rôles | Comptes bancaires (filtrés par rôle) |
| `/admin/` | admin, analyste | Vue synthèse |
| `/admin/dashboard` | admin, analyste | Dashboard temps réel WebSocket |
| `/admin/users` | admin | Gestion + verrouillage comptes |
| `/admin/events` | admin, analyste | Historique events filtrable |
| `/admin/alerts` | admin, analyste | Alertes + résolution |
| `ws://host/ws/alerts` | admin, analyste | Push alertes temps réel |

---

## 9. Installation

```bash
# Cloner
git clone https://github.com/votre-repo/xud-bank.git
cd xud-bank

# Environnement virtuel
python -m venv venv
source venv/bin/activate

# Dépendances
pip install -r requirements.txt
pip install bcrypt==4.0.1

# Configuration
cp .env.example .env
# Éditer .env avec vos valeurs Supabase

# BDD : exécuter dans Supabase SQL Editor
# 1. init_db.sql
# 2. seed_data.sql

# Lancer
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 10. Configuration

```env
DATABASE_URL=postgresql+asyncpg://postgres.[REF]:[PASSWORD]@aws-0-eu-west-1.pooler.supabase.com:6543/postgres
SECRET_KEY=votre_cle_secrete_32_chars_minimum
DEBUG=True

MAX_LOGIN_ATTEMPTS=3
BRUTE_FORCE_WINDOW=120

MASS_ACCESS_LIMIT=20
MASS_ACCESS_WINDOW=60

ENUM_USERNAMES_LIMIT=3
ENUM_WINDOW=300

ALLOWED_HOURS_START=7
ALLOWED_HOURS_END=20
```

---

## 11. Identifiants de test

> Hash bcrypt générés avec `passlib[bcrypt]` cost=12 — intégrés directement dans `seed_data.sql`.

| Username | Mot de passe | Rôle | Notes |
|---|---|---|---|
| `admin_sys` | `Admin@1234` | admin | Accès complet |
| `soc_analyst` | `Analyst@1234` | analyste | Dashboard + events + alerts |
| `jean.dupont` | `User@1234` | utilisateur | 2 comptes (public + confidentiel) |
| `marie.curie` | `User@1234` | utilisateur | 1 compte SECRET |
| `pierre.bank` | `User@1234` | utilisateur | 1 compte confidentiel |
| `locked_user` | `Lock@1234` | utilisateur | Compte verrouillé (démo brute force) |

### Comptes bancaires disponibles

| id_compte | Titulaire | Solde | Classification | Accessible par |
|---|---|---|---|---|
| XUD-FR-001-2024 | Jean Dupont | 15 750,00 € | confidentiel | jean.dupont, analyste, admin |
| XUD-FR-002-2024 | Jean Dupont | 3 200,00 € | public | tous |
| XUD-FR-003-2024 | Marie Curie | 87 430,50 € | **secret** | marie.curie, admin uniquement |
| XUD-FR-004-2024 | Pierre Bancroft | 4 980,75 € | confidentiel | pierre.bank, analyste, admin |
| XUD-INT-001-2024 | XUD-Bank Réserve | 5 000 000,00 € | **secret** | admin uniquement |

---

## 12. Scénarios de test

### Test 1 — Connexion normale
```
Identifiants : jean.dupont / User@1234
Résultat     : accès /data/accounts, event LOGIN_SUCCESS loggé, alerte OFF_HOURS si nuit
```

### Test 2 — Brute Force (Règle 1)
```
Action   : 3 tentatives avec mauvais mot de passe sur jean.dupont en < 2 min
Résultat : compte verrouillé, alerte MEDIUM dans /admin/alerts
```

### Test 3 — Injection SQL (Règle 2)
```
Action   : saisir  ' OR 1=1 --  dans le champ username
Résultat : requête rejetée (400), alerte HIGH dans /admin/alerts
```

### Test 4 — Accès admin non autorisé (Règle 3)
```
Action   : connecté en tant que jean.dupont → GET /admin/
Résultat : page 403, alerte HIGH dans /admin/alerts
```

### Test 5 — Exfiltration massive (Règle 4)
```bash
# Remplacer TON_COOKIE par la valeur du cookie xud_session
for i in $(seq 1 21); do
  curl -s -b "xud_session=TON_COOKIE" http://localhost:8000/data/accounts > /dev/null
  echo "Requête $i"
done
```
```
Résultat : alerte CRITICAL après la 20ème requête
```

### Test 6 — Énumération (Règle 5)
```bash
curl -X POST http://localhost:8000/auth/login -d "username=admin&password=test"
curl -X POST http://localhost:8000/auth/login -d "username=root&password=test"
curl -X POST http://localhost:8000/auth/login -d "username=superuser&password=test"
```
```
Résultat : alerte MEDIUM ENUM_ATTEMPT dans /admin/alerts
```

### Test 7 — Accès hors horaires (Règle 6)
```
Action   : se connecter entre 20h et 7h UTC
Résultat : alerte LOW OFF_HOURS_ACCESS loggée automatiquement
```

### Test 8 — URL suspecte
```
Action   : GET http://localhost:8000/admin/../../../etc/passwd
Résultat : page 403, alerte HIGH SUSPICIOUS_URL dans /admin/alerts
```

---

## 13. Journalisation

### Double cible

**Fichier `logs/security.log`** (rotation 5MB × 3)
```
2026-03-28 06:21:52 | INFO  | LOW    | OFF_HOURS_ACCESS | user=lux | ip=127.0.0.1 | Accès hors horaires...
2026-03-28 06:21:53 | INFO  | LOW    | LOGIN_SUCCESS    | user=lux | ip=127.0.0.1 | Connexion réussie...
2026-03-28 06:21:52 | INFO  | [ALERT-LOW] Connexion hors plage autorisée...
```

**Table `security_events`** en BDD → accessible via `/admin/events`.

### Champs journalisés

| Champ | Source |
|---|---|
| Date et heure | `datetime.utcnow()` |
| Utilisateur | Session / `anonymous` |
| IP source | `request.client.host` |
| Type d'événement | `EventType` enum |
| Gravité | `SeverityLevel` enum |
| Détail | Description contextuelle |
| Action entreprise | `action_taken` |
| Statut final | `open` / `closed` |

---

## Auteur

Projet développé dans le cadre de l'examen de Programmation Événementielle & Cybersécurité  
**UNIVERSITÉ DE KARA – FAST-LPSIC S6** | Année académique 2025-2026