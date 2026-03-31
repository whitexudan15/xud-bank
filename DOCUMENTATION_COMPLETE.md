# XUD-BANK — SecureDataMonitor
## Documentation Technique Complète

> **Université de Kara – FAST-LPSIC S6**  
> Programmation Événementielle & Cybersécurité | 2025-2026  
> Application Web bancaire sécurisée avec moteur de surveillance événementielle en temps réel

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture logicielle](#2-architecture-logicielle)
3. [Stack technologique](#3-stack-technologique)
4. [Structure du projet](#4-structure-du-projet)
5. [Modèle de données](#5-modèle-de-données)
6. [Base de données](#6-base-de-données)
7. [Authentification et autorisation](#7-authentification-et-autorisation)
8. [Moteur événementiel (Pub/Sub)](#8-moteur-événementiel-pubsub)
9. [Règles de détection SOC](#9-règles-de-détection-soc)
10. [Journalisation (Logging)](#10-journalisation-logging)
11. [WebSocket - Alertes temps réel](#11-websocket---alertes-temps-réel)
12. [Sécurité](#12-sécurité)
13. [Fonctionnalités de l'application](#13-fonctionnalités-de-lapplication)
14. [Module de surveillance événementielle](#14-module-de-surveillance-événementielle)
15. [Points forts de sécurité](#15-points-forts-de-sécurité)
16. [Comptes de test](#16-comptes-de-test)
17. [Installation et déploiement](#17-installation-et-déploiement)
18. [Tests des règles de détection](#18-tests-des-règles-de-détection)

---

## 1. Vue d'ensemble

**XUD-Bank** est une application Web bancaire de démonstration qui intègre un système complet de sécurité et de surveillance appelé **SecureDataMonitor**. Ce module agit comme un mini-SOC (Security Operations Center) capable de détecter, journaliser et alerter en temps réel toute activité suspecte sur le backend.

### Caractéristiques principales

- **Interface Premium** : UI moderne asynchrone avec Bootstrap 5, Jinja2, Chart.js
- **Authentification sécurisée** : Hachage Bcrypt (cost=12) exécuté en Threadpool pour éviter le blocage de l'Event Loop
- **Moteur événementiel Pub/Sub** : Architecture 100% découplée pour une scalabilité optimale
- **Détection proactive** : 6 règles de détection des menaces (Brute force, SQLi, exfiltration, etc.)
- **Surveillance WebSocket** : Dashboard supportant des centaines d'événements/seconde sans latence
- **Double journalisation** : Fichiers rotatifs locaux + persistance PostgreSQL

---

## 2. Architecture logicielle

Le projet combine deux design patterns architecturaux :

### 2.1 Layered Architecture (4 couches)

```
┌─────────────────────────────────────────────┐
│  PRÉSENTATION                               │
│  routers/ + templates/                      │
│  HTTP, vues HTML, WebSocket                 │
├─────────────────────────────────────────────┤
│  MÉTIER                                     │
│  services/auth_service.py                   │
│  Logique bancaire, Threadpool, Bcrypt       │
├─────────────────────────────────────────────┤
│  ÉVÉNEMENTIELLE                             │
│  events/dispatcher.py                       │
│  Pub/Sub, détection, alertes asynchrones    │
├─────────────────────────────────────────────┤
│  PERSISTANCE                                │
│  models/ + database.py                      │
│  CRUD SQLAlchemy 2.0 (asyncpg)              │
└─────────────────────────────────────────────┘
```

### 2.2 Pattern Pub/Sub (Observer)

- **Publishers** : Les routers publient des événements via `dispatcher.emit()`
- **Dispatcher** : Centralise et distribue les événements aux handlers abonnés
- **Subscribers** : Les handlers s'abonnent via `dispatcher.subscribe()`
- **Couplage zéro** : L'application bancaire et le moteur de surveillance sont totalement indépendants

---

## 3. Stack technologique

| Composant | Technologie | Détails |
|-----------|-------------|---------|
| **Backend** | FastAPI 0.115.6 | Framework Python asynchrone natif |
| **Langage** | Python 3.11+ | Fonctionnalités async modernes |
| **Base de données** | PostgreSQL (Railway) | Hébergé cloud avec driver asyncpg |
| **ORM** | SQLAlchemy 2.0.36 | Opérations totalement asynchrones |
| **Migrations** | Alembic 1.14.0 | Gestion des versions de schéma BDD |
| **Auth** | Passlib 1.7.4 (Bcrypt) | Hash cost=12 exécuté sur Threadpool |
| **Sessions** | itsdangerous 2.2.0 | Cookies signés et chiffrés sans BDD |
| **Validation** | Pydantic 2.10.3 | Schémas de validation intégrés FastAPI |
| **Templates** | Jinja2 3.1.4 | Rendu HTML server-side |
| **WebSocket** | WebSockets 13.1 + asyncio | Optimisation par batching (requestAnimationFrame) |
| **Frontend** | HTML5 / Bootstrap 5 / JS | Interfaces dynamiques avec Chart.js |
| **Logs** | logging.RotatingFileHandler | Rotation 5MB × 3 fichiers + QueueHandler async |
| **HTTP Client** | httpx 0.28.1 | Requêtes asynchrones pour tests/webhooks |
| **Date/Time** | python-dateutil 2.9.0 | Manipulation temporelle avancée |

---

## 4. Structure du projet

```
xud-bank/
├── app/                              # Application Bancaire Principale
│   ├── main.py                       # Point d'entrée FastAPI, middlewares, lifespan
│   ├── database.py                   # Configuration AsyncSession + Railway PostgreSQL
│   ├── config.py                     # Settings Pydantic (variables .env)
│   │
│   ├── models/                       # Modèles SQLAlchemy
│   │   ├── __init__.py
│   │   ├── user.py                   # Table users (UUID, rôle, is_locked)
│   │   ├── bank_account.py           # Table bank_accounts (données sensibles)
│   │   ├── security_event.py         # Table security_events (journal central)
│   │   ├── alert.py                  # Table alerts (liées aux events)
│   │   └── login_attempt.py          # Table login_attempts (tracking)
│   │
│   ├── routers/                      # Routes HTTP API
│   │   ├── __init__.py
│   │   ├── auth.py                   # Authentification (login/logout/register)
│   │   └── data.py                   # Accès aux données bancaires
│   │
│   ├── services/                     # Logique métier
│   │   └── auth_service.py           # Hash password, sessions, CRUD utilisateurs
│   │
│   ├── templates/                    # Templates HTML (Front public)
│   │   ├── base.html                 # Template de base
│   │   ├── login.html                # Page de connexion
│   │   ├── register.html             # Page d'inscription
│   │   └── data.html                 # Page des comptes
│   │
│   └── static/css/
│       └── base.css                  # Styles globaux
│
├── secureDataMonitor/                # Module SOC de Surveillance
│   ├── __init__.py
│   │
│   ├── events/                       # Système événementiel
│   │   ├── __init__.py
│   │   ├── dispatcher.py             # EventDispatcher (Pub/Sub central)
│   │   └── handlers.py               # Handlers abonnés aux événements
│   │
│   ├── services/                     # Services du monitor
│   │   ├── __init__.py
│   │   ├── detection.py              # Règles de détection (6 règles)
│   │   └── logger.py                 # Journalisation fichier + BDD
│   │
│   ├── routers/                      # Routes Admin & WebSocket
│   │   ├── __init__.py
│   │   ├── admin.py                  # Dashboard admin (CRUD alerts/events)
│   │   └── api_alerts.py             # Endpoint WebSocket + API REST
│   │
│   ├── templates/                    # Templates Admin
│   │   ├── dashboard.html            # Dashboard principal SOC
│   │   ├── admin/                    # Vues administration
│   │   │   ├── index.html
│   │   │   ├── alerts.html           # Gestion des alertes
│   │   │   ├── events.html           # Historique événements
│   │   │   ├── users.html            # Gestion utilisateurs
│   │   │   ├── new_user.html         # Création utilisateur
│   │   │   └── clear_data.html       # Nettoyage données
│   │   └── errors/                   # Pages d'erreur customisées
│   │       ├── 401.html
│   │       ├── 403.html
│   │       ├── 404.html
│   │       └── 500.html
│   │
│   └── static/js/
│       └── ws_alerts.js              # Client WebSocket haute performance
│
├── logs/                             # Logs fichiers (rotation automatique)
│   └── security.log                  # Journal des événements de sécurité
│
├── .env                              # Variables d'environnement (secrets)
├── .env.example                      # Exemple de configuration
├── requirements.txt                  # Dépendances Python
├── init_db.sql                       # Script création tables PostgreSQL
├── seed_data.sql                     # Données de test initiales
├── Procfile                          # Configuration déploiement (Railway/Heroku)
└── README.md                         # Documentation projet
```

---

## 5. Modèle de données

### 5.1 Table `users`

**Description** : Stocke les identifiants et informations des utilisateurs.

| Colonne | Type | Contraintes | Description |
|---------|------|-------------|-------------|
| `id` | UUID | PK, DEFAULT gen_random_uuid() | Identifiant unique |
| `username` | VARCHAR(50) | UNIQUE, NOT NULL | Nom d'utilisateur |
| `email` | VARCHAR(100) | UNIQUE, NOT NULL | Email (utilisé pour login) |
| `password_hash` | VARCHAR(255) | NOT NULL | Hash bcrypt du mot de passe |
| `role` | user_role (ENUM) | NOT NULL, DEFAULT 'utilisateur' | Rôle (admin/directeur/comptable/utilisateur) |
| `is_locked` | BOOLEAN | NOT NULL, DEFAULT FALSE | Verrouillé après brute force |
| `failed_attempts` | INTEGER | NOT NULL, DEFAULT 0 | Compteur échecs connexion |
| `last_failed_at` | TIMESTAMP | NULL | Date dernier échec |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT NOW() | Date création compte |

**Index** :
- `idx_users_email` : Recherche rapide par email
- `idx_users_is_locked` : Filtrage comptes verrouillés

### 5.2 Table `bank_accounts`

**Description** : Données bancaires sensibles (cibles de la surveillance).

| Colonne | Type | Contraintes | Description |
|---------|------|-------------|-------------|
| `id` | UUID | PK | Identifiant unique |
| `id_compte` | VARCHAR(20) | UNIQUE, NOT NULL | Numéro de compte |
| `titulaire` | VARCHAR(100) | NOT NULL | Nom du titulaire |
| `solde` | DECIMAL(15,2) | NOT NULL, DEFAULT 0.00 | Solde du compte |
| `historique` | TEXT | NULL | JSON des transactions |
| `classification` | account_classification (ENUM) | NOT NULL, DEFAULT 'confidentiel' | Niveau sensibilité (public/confidentiel/secret) |
| `owner_id` | UUID | FK → users.id, CASCADE | Propriétaire du compte |
| `created_at` | TIMESTAMP | NOT NULL, DEFAULT NOW() | Date création |

**Relation** : `BankAccount.owner` ←→ `User.accounts` (lazy="joined")

### 5.3 Table `login_attempts`

**Description** : Tracking des tentatives de connexion pour Règle 1 (Brute force) et Règle 5 (Énumération).

| Colonne | Type | Contraintes | Description |
|---------|------|-------------|-------------|
| `id` | UUID | PK | Identifiant unique |
| `ip_address` | INET | NOT NULL | Adresse IP source |
| `username_tried` | VARCHAR(50) | NOT NULL | Username tenté |
| `timestamp` | TIMESTAMP | NOT NULL, DEFAULT NOW() | Date tentative |
| `success` | BOOLEAN | NOT NULL | Succès ou échec |

**Index** :
- `idx_login_attempts_username_success_time` : Détection brute force
- `idx_login_attempts_ip_time` : Détection énumération

### 5.4 Table `security_events`

**Description** : Journal central indélébile de tous les événements de sécurité.

| Colonne | Type | Contraintes | Description |
|---------|------|-------------|-------------|
| `id` | UUID | PK | Identifiant unique |
| `timestamp` | TIMESTAMP | NOT NULL, DEFAULT NOW() | Horodatage |
| `username` | VARCHAR(50) | NULL | Utilisateur impliqué (NULL si inconnu) |
| `ip_address` | INET | NOT NULL | IP source |
| `event_type` | event_type (ENUM) | NOT NULL | Type d'événement |
| `severity` | severity_level (ENUM) | NOT NULL | Gravité (LOW/MEDIUM/HIGH/CRITICAL) |
| `description` | TEXT | NOT NULL | Détail complet |
| `status` | event_status (ENUM) | NOT NULL, DEFAULT 'open' | Statut (open/investigating/closed) |
| `action_taken` | TEXT | NULL | Action entreprise |

**Types d'événements (ENUM)** :
- `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_LOCKED`
- `UNKNOWN_USER`, `UNAUTHORIZED_ACCESS`, `PRIVILEGE_ESCALATION`
- `SQL_INJECTION`, `RATE_LIMIT`, `MASS_DATA_ACCESS`
- `ENUM_ATTEMPT`, `OFF_HOURS_ACCESS`, `SUSPICIOUS_URL`

**Index** :
- `idx_security_events_timestamp`
- `idx_security_events_type_timestamp`
- `idx_security_events_severity_timestamp`
- `idx_security_events_ip`

### 5.5 Table `alerts`

**Description** : Alertes générées par le SOC, liées aux security_events.

| Colonne | Type | Contraintes | Description |
|---------|------|-------------|-------------|
| `id` | UUID | PK | Identifiant unique |
| `timestamp` | TIMESTAMP | NOT NULL, DEFAULT NOW() | Horodatage |
| `alert_level` | severity_level (ENUM) | NOT NULL | Niveau d'alerte |
| `source_event_id` | UUID | FK → security_events.id, CASCADE | Événement déclencheur |
| `message` | TEXT | NOT NULL | Message d'alerte |
| `resolved` | BOOLEAN | NOT NULL, DEFAULT FALSE | Résolue ou non |

**Relation** : `Alert.source_event` ←→ `SecurityEvent.alerts` (backref)

**Index** :
- `idx_alerts_resolved_timestamp` : Filtrage alertes non résolues

---

## 6. Base de données

### 6.1 Configuration PostgreSQL

- **Driver** : `asyncpg` (driver asynchrone haute performance)
- **Pool de connexions** :
  - `pool_size=20` : Connexions maintenues actives
  - `max_overflow=20` : Connexions supplémentaires temporaires
  - `pool_timeout=30s` : Délai avant timeout
  - `pool_recycle=1800s` : Recyclage toutes les 30 min (Railway)
  - `pool_pre_ping=True` : Vérification avant utilisation

### 6.2 Sessions asynchrones

```python
# Session factory (database.py)
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Dependency injection FastAPI
async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
```

### 6.3 Extensions PostgreSQL

- `pgcrypto` : Génération d'UUID (`gen_random_uuid()`)
- Type `INET` : Stockage natif des adresses IP

---

## 7. Authentification et autorisation

### 7.1 Hachage des mots de passe

**Algorithme** : Bcrypt avec cost factor = 12  
**Exécution** : Threadpool (via `run_in_threadpool`) pour éviter le blocage de l'Event Loop asyncio.

```python
async def hash_password(plain: str) -> str:
    return await run_in_threadpool(pwd_context.hash, plain)

async def verify_password(plain: str, hashed: str) -> bool:
    return await run_in_threadpool(pwd_context.verify, plain, hashed)
```

### 7.2 Gestion des sessions

**Mécanisme** : Cookies signés avec `itsdangerous.URLSafeTimedSerializer`  
**Durée** : 1 heure (configurable via `SESSION_MAX_AGE`)  
**Stockage** : Côté client (pas de session en BDD)

```python
def create_session_token(user: User) -> str:
    data = {
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role.value,
    }
    return serializer.dumps(data, salt="session")

def decode_session_token(token: str) -> dict | None:
    try:
        data = serializer.loads(token, salt="session", max_age=3600)
        return data
    except (BadSignature, SignatureExpired):
        return None
```

### 7.3 Rôles et permissions

**4 rôles définis** :
1. **admin** : Accès complet au dashboard SOC (création utilisateurs, gestion alertes)
2. **directeur** : Accès aux bilans et données sensibles
3. **comptable** : Accès aux comptes et opérations bancaires
4. **utilisateur** : Consultation des comptes personnels uniquement

**Middleware d'autorisation** :
```python
def require_role(*roles: str):
    def _checker(request: Request) -> dict:
        user_data = require_login(request)
        if user_data["role"] not in roles:
            raise HTTPException(status_code=403, detail="Accès refusé")
        return user_data
    return _checker
```

### 7.4 Flux d'authentification

```
1. POST /auth/login (email, password)
   ↓
2. Validation inputs (SQL injection, caractères suspects)
   ↓
3. authenticate(db, email, password)
   ├─→ Utilisateur inexistant → UNKNOWN_USER event
   ├─→ Compte verrouillé → ACCOUNT_LOCKED event
   └─→ Password incorrect → LOGIN_FAILED event + incrémente compteur
   ↓
4. Si succès :
   ├─→ Check hors horaires → OFF_HOURS_ACCESS event
   ├─→ Création token session
   └─→ LOGIN_SUCCESS event + redirect selon rôle
```

---

## 8. Moteur événementiel (Pub/Sub)

### 8.1 Architecture du Dispatcher

**Classe** : `EventDispatcher` (singleton global)  
**Pattern** : Publish/Subscribe asynchrone  
**Objectif** : Découplage total entre publishers (routers) et subscribers (handlers)

```python
class EventDispatcher:
    def __init__(self):
        self._listeners: dict[str, list[Callable]] = defaultdict(list)
        self._background_tasks: set[asyncio.Task] = set()

    def subscribe(self, event_name: str, handler: Callable) -> None:
        """Abonne un handler à un événement."""
        if handler not in self._listeners[event_name]:
            self._listeners[event_name].append(handler)

    async def emit(self, event_name: str, data: dict) -> None:
        """Publie un événement (fire-and-forget)."""
        handlers = self._listeners.get(event_name, [])
        for handler in handlers:
            task = asyncio.create_task(self._safe_call(handler, event_name, data))
            self._background_tasks.add(task)
            task.add_done_callback(self._task_done)
```

### 8.2 Caractéristiques clés

- **Non-bloquant** : Les handlers s'exécutent en tâches de fond (`asyncio.create_task`)
- **Fire-and-forget** : L'émetteur ne bloque pas, retourne immédiatement
- **Gestion d'erreurs isolée** : Chaque handler a son propre try/except
- **Background tasks cleanup** : Callback `_task_done` nettoie les tâches terminées

### 8.3 Événements publiés

| Événement | Publisher | Payload typique |
|-----------|-----------|-----------------|
| `login_success` | auth.py | `{ip, username, role}` |
| `login_failed` | auth.py | `{ip, username, attempt}` |
| `account_locked` | handlers.py | `{ip, username}` |
| `unknown_user` | auth.py | `{ip, username}` |
| `unauthorized` | main.py (exception 403) | `{ip, username, role, path}` |
| `privilege_escalation` | handlers.py | `{ip, username, detail}` |
| `rate_limit` | data.py | `{ip, username, count, window}` |
| `mass_data_access` | handlers.py | `{ip, username, count, window}` |
| `off_hours_access` | auth.py | `{ip, username, hour}` |
| `sql_injection` | auth.py | `{ip, username, field, payload}` |
| `enum_attempt` | handlers.py | `{ip, count, source_event_id}` |
| `suspicious_url` | main.py (middleware) | `{ip, url, username}` |

### 8.4 Enregistrement des handlers

Appelé une fois au démarrage dans `main.py` (lifespan) :

```python
def register_all_handlers() -> None:
    # Auth
    dispatcher.subscribe("login_success", handle_login_success)
    dispatcher.subscribe("login_failed", handle_failed_login)
    dispatcher.subscribe("account_locked", handle_account_locked)
    dispatcher.subscribe("unknown_user", handle_unknown_user)
    
    # Autorisation
    dispatcher.subscribe("unauthorized", handle_unauthorized)
    dispatcher.subscribe("privilege_escalation", handle_privilege_escalation)
    
    # Applicatifs
    dispatcher.subscribe("rate_limit", handle_rate_limit)
    dispatcher.subscribe("mass_data_access", handle_mass_access)
    dispatcher.subscribe("off_hours_access", handle_off_hours)
    
    # Attaques
    dispatcher.subscribe("sql_injection", handle_sql_injection)
    dispatcher.subscribe("enum_attempt", handle_enum_attempt)
    dispatcher.subscribe("suspicious_url", handle_suspicious_url)
```

---

## 9. Règles de détection SOC

### 9.1 Règle 1 — Brute Force Login

**Déclencheur** : 3 échecs de connexion sur un même compte en moins de 2 minutes

**Détection** :
```python
async def check_brute_force(db, username, ip) -> bool:
    window_start = datetime.utcnow() - timedelta(seconds=120)
    count = await db.execute(
        select(func.count(LoginAttempt.id))
        .where(username_tried == username, success == False, timestamp >= window_start)
    )
    return count >= 3
```

**Réaction automatique** :
- ✅ Verrouillage du compte (`is_locked = TRUE`)
- ✅ Réinitialisation du compteur d'échecs
- ✅ Alerte **MEDIUM** créée
- ✅ Événement `LOGIN_LOCKED` généré

**Gravité** : MEDIUM

---

### 9.2 Règle 2 — Injection SQL

**Déclencheur** : Patterns SQL injection détectés dans les inputs utilisateur

**Patterns détectés** (regex compiled) :
```python
SQL_INJECTION_PATTERNS = [
    r"(?:'|\"|`)\s*(?:or|and|\|\||&&)\s+[\w'\"` ]+\s*=\s*[\w'\"` ]+",  # ' OR 'a'='a
    r"\b(?:or|and)\s+\d+\s*=\s*\d+",                                    # OR 1=1
    r"\bunion\s+(?:all\s+)?select\s+@@version",                         # UNION SELECT
    r";\s*(?:drop|delete|update|insert|exec|truncate|create|alter)\b",   # Stacked queries
    r"'\s+and\s+\d+\s*=\s*\d+\s*--",                                    # Boolean-based blind
    r"%(?:27|22|3b|2d%2d|3d|2f%2a)",                                    # URL-encoded
    r"<script[\s>]",                                                    # XSS context
]
```

**Réaction automatique** :
- ✅ Rejet immédiat de la requête (HTTP 400)
- ✅ Alerte **HIGH** créée
- ✅ Payload enregistré dans l'événement

**Gravité** : HIGH

---

### 9.3 Règle 3 — Accès Admin non autorisé

**Déclencheur** : Utilisateur sans rôle `admin` tente d'accéder à `/admin/*`

**Détection** :
```python
def check_admin_access(path: str, role: str) -> bool:
    return path.startswith("/admin") and role != "admin"
```

**Réaction automatique** :
- ✅ Accès refusé (HTTP 403 Forbidden)
- ✅ Alerte **HIGH** créée
- ✅ Événement `UNAUTHORIZED_ACCESS` généré

**Gravité** : HIGH

---

### 9.4 Règle 4 — Exfiltration massive

**Déclencheur** : Plus de 20 consultations de données sensibles en moins d'1 minute

**Détection** (compteur en mémoire) :
```python
_access_counters: dict[str, list[datetime]] = {}

def record_data_access(username: str) -> tuple[bool, int]:
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=60)
    
    if username not in _access_counters:
        _access_counters[username] = []
    
    # Purge anciens accès
    _access_counters[username] = [t for t in _access_counters[username] if t >= window_start]
    _access_counters[username].append(now)
    
    count = len(_access_counters[username])
    return count >= 20, count
```

**Réaction automatique** :
- ✅ Alerte **CRITICAL** créée
- ✅ Utilisateur flaggé comme suspect
- ✅ Notification immédiate au SOC via WebSocket

**Gravité** : CRITICAL

---

### 9.5 Règle 5 — Énumération d'identifiants

**Déclencheur** : Même IP ayant tenté 3 usernames différents en moins de 5 minutes

**Détection** :
```python
async def check_enumeration(db, ip) -> tuple[bool, int]:
    window_start = datetime.utcnow() - timedelta(seconds=300)
    count = await db.execute(
        select(func.count(distinct(LoginAttempt.username_tried)))
        .where(ip_address == ip, success == False, timestamp >= window_start)
    )
    return count >= 3, count
```

**Réaction automatique** :
- ✅ Alerte **MEDIUM** créée
- ✅ IP enregistrée comme suspecte
- ✅ Événement `ENUM_ATTEMPT` généré

**Gravité** : MEDIUM

---

### 9.6 Règle 6 — Accès hors horaires

**Déclencheur** : Connexion en dehors de la plage 07h00 - 20h00 UTC

**Détection** :
```python
def check_off_hours(hour: int | None = None) -> bool:
    current_hour = hour if hour is not None else datetime.utcnow().hour
    return not (settings.ALLOWED_HOURS_START <= current_hour < settings.ALLOWED_HOURS_END)
# Retourne True si hors horaires (avant 7h ou après 20h)
```

**Réaction automatique** :
- ✅ Connexion réussie mais journalisée
- ✅ Alerte **LOW** créée
- ✅ Heure de connexion enregistrée

**Gravité** : LOW

---

### 9.7 Détection URL suspectes (Extension Règle 3)

**Déclencheur** : Patterns de path traversal ou fichiers sensibles dans l'URL

**Patterns détectés** :
```python
SUSPICIOUS_URL_PATTERNS = [
    r"(?:\.\.[\\/]){2,}",         # ../../..
    r"/etc/passwd",
    r"/etc/shadow",
    r"\.php$",                    # Fichiers PHP
    r"\.asp$",                    # Fichiers ASP
    r"wp-admin",                  # Admin WordPress
    r"phpMyAdmin",                # phpMyAdmin
    r"\.env$",                    # Fichier .env
    r"\.git/",                    # Dossier .git
]
```

**Réaction automatique** :
- ✅ Requête bloquée (HTTP 403)
- ✅ Alerte **HIGH** créée
- ✅ Événement `SUSPICIOUS_URL` généré

**Gravité** : HIGH

---

## 10. Journalisation (Logging)

### 10.1 Double cible de journalisation

Le système implémente une **double journalisation** pour garantir la traçabilité complète :

1. **Fichier local** : `logs/security.log` (RotatingFileHandler)
2. **Base de données** : Table `security_events` (PostgreSQL)

### 10.2 Logger fichier asynchrone

**Configuration** :
- **Handler** : `RotatingFileHandler` (5 MB × 3 fichiers)
- **QueueHandler** : Écriture non-bloquante via queue + thread dédié
- **Format** : Structuré avec timestamp, sévérité, type, utilisateur, IP, description

```python
def setup_file_logger() -> logging.Logger:
    os.makedirs("logs", exist_ok=True)
    
    file_handler = RotatingFileHandler(
        filename="logs/security.log",
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=3,
        encoding="utf-8",
    )
    
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    
    # QueueHandler pour async
    log_queue = queue.Queue(-1)
    queue_handler = QueueHandler(log_queue)
    
    # QueueListener traite dans un thread
    _queue_listener = QueueListener(log_queue, file_handler)
    _queue_listener.start()
```

**Format des logs** :
```
2026-03-27 14:32:11 | MEDIUM   | LOGIN_FAILED | user=jdoe              | ip=192.168.1.45     | Échec connexion #3 pour 'jdoe' depuis 192.168.1.45 | action=Compteur inchangé | status=open | id=abc123...
```

### 10.3 Journalisation en base de données

```python
async def log_event(
    db: AsyncSession,
    event_type: EventType,
    severity: SeverityLevel,
    ip_address: str,
    description: str,
    username: str | None = None,
    action_taken: str | None = None,
    status: EventStatus = EventStatus.open,
) -> SecurityEvent:
    # 1. Persistance BDD
    event = SecurityEvent(
        timestamp=datetime.utcnow(),
        username=username,
        ip_address=ip_address,
        event_type=event_type,
        severity=severity,
        description=description,
        status=status,
        action_taken=action_taken,
    )
    db.add(event)
    await db.flush()  # Obtient l'ID sans commit
    
    # 2. Fichier log structuré
    _write_to_file(...)
    
    return event
```

### 10.4 Champs journalisés (exigences complètes)

Chaque événement inclut systématiquement :
- ✅ **Date/heure** : `timestamp` (UTC)
- ✅ **Utilisateur** : `username` (ou NULL si inconnu)
- ✅ **IP source** : `ip_address` (type INET PostgreSQL)
- ✅ **Type d'événement** : `event_type` (ENUM à 12 valeurs)
- ✅ **Gravité** : `severity` (LOW/MEDIUM/HIGH/CRITICAL)
- ✅ **Détail** : `description` (texte complet)
- ✅ **Action entreprise** : `action_taken` (mesure automatique)
- ✅ **Statut final** : `status` (open/investigating/closed)

---

## 11. WebSocket - Alertes temps réel

### 11.1 Architecture WebSocket

**Endpoint** : `ws://host/ws/alerts`  
**Protocole** : WebSocket natif avec heartbeat 30s  
**Client** : Dashboard SOC (JavaScript avec batching `requestAnimationFrame`)

### 11.2 Connection Manager

Gère toutes les connexions actives et le broadcast :

```python
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    async def broadcast(self, data: dict):
        message = json.dumps(data, default=str)
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        # Nettoie connexions mortes
        for ws in dead:
            self.disconnect(ws)
```

### 11.3 Types de messages

#### Message d'initialisation (serveur → client)
```json
{
  "type": "init",
  "stats": {
    "unresolved_alerts": 5,
    "total_events": 142,
    "connected_clients": 3
  },
  "recent_alerts": [
    {
      "id": "uuid",
      "timestamp": "2026-03-27T14:32:11",
      "alert_level": "HIGH",
      "message": "Accès non autorisé à /admin/dashboard..."
    }
  ]
}
```

#### Nouvelle alerte (broadcast)
```json
{
  "type": "new_alert",
  "alert": {
    "id": "uuid",
    "timestamp": "2026-03-27T14:32:11",
    "alert_level": "CRITICAL",
    "message": "EXFILTRATION MASSIVE : 25 accès aux données sensibles...",
    "resolved": false,
    "source_event_id": "uuid"
  }
}
```

#### Nouvel événement
```json
{
  "type": "new_event",
  "event": {
    "id": "uuid",
    "timestamp": "2026-03-27T14:32:11",
    "event_type": "SQL_INJECTION",
    "severity": "HIGH",
    "username": "anonymous",
    "ip_address": "192.168.1.100",
    "description": "Pattern SQL injection détecté dans champ 'email'..."
  }
}
```

#### Heartbeat (ping/pong)
```json
// Serveur → Client
{
  "type": "heartbeat",
  "timestamp": "2026-03-27T14:32:11",
  "connected_clients": 3
}

// Client → Serveur
{
  "type": "ping"
}

// Serveur → Client (réponse)
{
  "type": "pong",
  "timestamp": "2026-03-27T14:32:11",
  "connected_clients": 3
}
```

### 11.4 Optimisations de performance

1. **Cache initial (5s TTL)** :
   - Évite les requêtes BDD répétées à chaque connexion client
   - Les 5 dernières alertes sont mises en cache avec timestamp

2. **Batching visuel** :
   - Le client utilise `requestAnimationFrame` pour regrouper les mises à jour DOM
   - Supporte des centaines d'événements/seconde sans reflow excessif

3. **Nettoyage automatique** :
   - Les connexions mortes sont automatiquement retirées de la liste
   - Gestion gracieuse des déconnexions

---

## 12. Sécurité

### 12.1 Middleware de sécurité globale

Appliqué à toutes les requêtes HTTP :

```python
class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # 1. Vérification URL suspecte
        if check_suspicious_url(path):
            await dispatcher.emit("suspicious_url", {...})
            return HTMLResponse(status_code=403)
        
        response = await call_next(request)
        
        # 2. Headers de sécurité HTTP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response
```

### 12.2 Headers de sécurité

| Header | Valeur | Protection |
|--------|--------|------------|
| `X-Content-Type-Options` | nosniff | Empêche MIME sniffing |
| `X-Frame-Options` | DENY | Empêche clickjacking |
| `X-XSS-Protection` | 1; mode=block | Active filtre XSS navigateur |
| `Referrer-Policy` | strict-origin-when-cross-origin | Contrôle Referer header |

### 12.3 Protection anti-énumération

**Message d'erreur générique** :
- côté client : "Email ou mot de passe incorrect."
- côté serveur : Détails précis (`unknown_user`, `account_locked`, `invalid_password`)

Cette approche empêche un attaquant de distinguer :
- Un utilisateur inexistant
- Un mot de passe incorrect
- Un compte verrouillé

### 12.4 Validation des inputs

Tous les champs utilisateur sont validés avant traitement :

```python
def validate_inputs(fields: dict) -> tuple[bool, str, str]:
    for field_name, value in fields.items():
        if check_sql_injection(value):
            return True, field_name, value
        if check_special_characters(value, field_name):
            return True, field_name, value
    return False, "", ""
```

### 12.5 Cookies sécurisés

Configuration des cookies de session :
- `HttpOnly=True` : Inaccessible au JavaScript (anti-XSS)
- `SameSite=Lax` : Protection CSRF
- `Max-Age=3600` : Expiration après 1 heure
- Signés cryptographiquement avec `itsdangerous`

---

## 13. Fonctionnalités de l'application

### 13.1 Module bancaire (app/)

#### Authentification
- **GET/POST /auth/login** : Page de connexion avec validation inputs
- **GET /auth/logout** : Déconnexion et suppression cookie
- **GET/POST /auth/register** : Création de compte utilisateur

#### Données bancaires
- **GET /data/accounts** : Liste des comptes bancaires (filtrage par rôle)
- **GET /data/accounts/{id}** : Détail d'un compte spécifique
- **GET /data/transactions** : Historique des transactions

#### Templates HTML
- `login.html` : Formulaire de connexion avec messages d'erreur
- `register.html` : Formulaire d'inscription avec validation
- `data.html` : Affichage des comptes avec Chart.js
- `base.html` : Template de base avec navbar responsive

### 13.2 Module SOC (secureDataMonitor/)

#### Dashboard admin
- **GET /admin/dashboard** : Vue d'ensemble (stats, graphiques)
- **GET /admin/alerts** : Gestion des alertes (résolution, filtrage)
- **GET /admin/events** : Historique complet des événements
- **GET /admin/users** : Gestion des utilisateurs (CRUD)
- **POST /admin/users/create** : Création manuelle d'utilisateur
- **POST /admin/data/clear** : Nettoyage des données de test

#### API REST
- **GET /api/alerts/recent** : Dernières alertes non résolues (fallback polling)
- **GET /api/stats** : Statistiques globales (events, alertes, comptes verrouillés)

#### WebSocket
- **WS /ws/alerts** : Flux temps réel des alertes et événements

#### Pages d'erreur customisées
- `401.html` : Non authentifié
- `403.html` : Accès refusé
- `404.html` : Page non trouvée
- `500.html` : Erreur serveur

---

## 14. Module de surveillance événementielle

### 14.1 Composants principaux

#### Dispatcher (secureDataMonitor/events/dispatcher.py)
- **Rôle** : Centralise et distribue les événements
- **Pattern** : Pub/Sub asynchrone
- **Caractéristiques** : Fire-and-forget, non-bloquant

#### Handlers (secureDataMonitor/events/handlers.py)
- **Rôle** : Traitent les événements reçus
- **Actions** :
  1. Appellent `detection.py` pour vérifier les règles
  2. Appellent `logger.py` pour journaliser
  3. Créent des alertes si règle franchie
  4. Effectuent actions automatiques (verrouillage, blocage)

#### Détection (secureDataMonitor/services/detection.py)
- **Rôle** : Implémente les 6 règles de détection
- **Fonctions clés** :
  - `check_brute_force()` : Règle 1
  - `check_sql_injection()` : Règle 2 (synchrone)
  - `check_admin_access()` : Règle 3
  - `record_data_access()` : Règle 4 (compteur mémoire)
  - `check_enumeration()` : Règle 5
  - `check_off_hours()` : Règle 6

#### Logger (secureDataMonitor/services/logger.py)
- **Rôle** : Double journalisation (fichier + BDD)
- **Fonctions clés** :
  - `log_event()` : Crée un SecurityEvent
  - `create_alert()` : Crée une Alert liée
  - `resolve_alert()` : Marque une alerte comme résolue
  - `close_event()` : Passe un event en statut 'closed'

### 14.2 Flux de traitement complet

```
Requête HTTP → Router (auth.py, data.py)
    ↓
Validation inputs (SQL injection, chars suspects)
    ↓
Action métier (authenticate, fetch data)
    ↓
Émission événement → dispatcher.emit("event_name", data)
    ↓
Handlers abonnés (exécution background)
    ├─→ Détection (check_* functions)
    ├─→ Logging (log_event + create_alert)
    ├─→ Actions automatiques (lock_account, etc.)
    └─→ Broadcast WebSocket (si alerte créée)
    ↓
Réponse HTTP à l'utilisateur
```

**Exemple concret** : Tentative de brute force

```
1. POST /auth/login (email=admin@xud.com, password=wrong)
2. authenticate() → échec password
3. dispatcher.emit("login_failed", {ip, username, attempt=1})
4. Handler handle_failed_login() exécute en background :
   ├─→ record_login_attempt(db, ip, username, success=False)
   ├─→ check_brute_force(db, username, ip) → False (1 < 3)
   ├─→ log_event(LOGIN_FAILED, MEDIUM, ...)
   └─→ broadcast_event(event)
5. Réponse HTTP : "Email ou mot de passe incorrect."
```

**Deuxième échec** :
```
1. login_failed → attempt=2
2. check_brute_force() → False (2 < 3)
3. log_event + broadcast
```

**Troisième échec** :
```
1. login_failed → attempt=3
2. check_brute_force() → True (3 >= 3)
3. lock_account(db, username) → is_locked=TRUE
4. create_alert(MEDIUM, "Brute force détecté...")
5. broadcast_alert(alert) → Dashboard SOC notifié en temps réel
6. dispatcher.emit("account_locked", {ip, username})
7. handle_account_locked() → log_event(LOGIN_LOCKED, ...)
```

---

## 15. Points forts de sécurité

### 15.1 Architecture sécurisée

✅ **Threadpool pour bcrypt** : Évite le blocage de l'Event Loop asyncio  
✅ **Sessions signées** : Pas de stockage BDD, expiration automatique  
✅ **Couplage zéro** : Le module SOC peut être retiré sans casser l'app  
✅ **Async everywhere** : SQLAlchemy async, asyncpg, FastAPI natif  

### 15.2 Protection des données

✅ **Hash bcrypt cost=12** : Standard industriel (OWASP)  
✅ **UUID pour toutes les PK** : Impossible à deviner par énumération  
✅ **Cookies HttpOnly + SameSite** : Protection XSS + CSRF  
✅ **Headers HTTP sécurisés** : X-Frame-Options, X-XSS-Protection, etc.  

### 15.3 Détection proactive

✅ **6 règles de détection** : Couverture large des attaques courantes  
✅ **Temps réel** : WebSocket avec broadcasting instantané  
✅ **Double logging** : Fichier + BDD pour audit complet  
✅ **Alertes hiérarchisées** : LOW, MEDIUM, HIGH, CRITICAL  

### 15.4 Performance et scalabilité

✅ **Pool de connexions** : 20 connexions + 20 overflow (Railway)  
✅ **QueueHandler** : Logging non-bloquant via thread dédié  
✅ **Fire-and-forget** : Handlers exécutés en background  
✅ **Cache WebSocket** : 5s TTL pour éviter requêtes BDD répétées  
✅ **Batching DOM** : requestAnimationFrame pour centaines d'events/sec  

### 15.5 Traçabilité complète

✅ **Tous les événements journalisés** : username, IP, timestamp, description  
✅ **Actions automatiques tracées** : `action_taken` dans chaque event  
✅ **Statuts suivis** : open → investigating → closed  
✅ **Alertes liées aux events** : Relation source_event_id  

---

## 16. Comptes de test

Voici les identifiants pré-configurés dans `seed_data.sql` :

| Username | Email | Mot de passe | Rôle | Accès & Privilèges |
|----------|-------|--------------|------|-------------------|
| **soc** | `soc@xud-bank.com` | `Soc@1234` | **admin** | Dashboard SOC complet (gestion alertes, utilisateurs, events) |
| **hor** | `hor@xud-bank.com` | `Hor@1234` | **comptable** | Accès aux bilans et comptes |
| **directeur** | `directeur@xud-bank.com` | `Directeur@1234` | **directeur** | Accès directoire (données sensibles) |
| **dupont** | `dupont@mail.com` | `Dupont@1234` | **utilisateur** | Consultation comptes personnels uniquement |
| **pierre** | `pierre@mail.com` | `Pierre@1234` | **utilisateur** | Consultation comptes personnels uniquement |

**Redirection après login** :
- **admin** → `/admin/dashboard`
- **autres rôles** → `/data/accounts`

---

## 17. Installation et déploiement

### 17.1 Prérequis

- Python 3.11+
- PostgreSQL 14+ (local ou cloud type Railway)
- pip (gestionnaire de paquets Python)

### 17.2 Installation locale

```bash
# 1. Cloner le repository
git clone https://github.com/whitexudan15/xud-bank.git
cd xud-bank

# 2. Créer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
.\venv\Scripts\activate   # Windows

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos valeurs :
# - DATABASE_URL (postgresql+asyncpg://...)
# - SECRET_KEY (min 32 caractères)
# - DEBUG (True/False)

# 5. Initialiser la base de données
psql $DATABASE_URL < init_db.sql
psql $DATABASE_URL < seed_data.sql

# 6. Lancer l'application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 17.3 Variables d'environnement (.env)

```ini
# Application
APP_NAME=XUD-Bank
APP_VERSION=1.0.0
DEBUG=True

# Database (Railway PostgreSQL)
DATABASE_URL=postgresql+asyncpg://user:password@host:5432/dbname

# Sécurité sessions
SECRET_KEY=votre_clé_secrète_min_32_chars
SESSION_COOKIE_NAME=xud_session
SESSION_MAX_AGE=3600

# Règle 1 : Brute Force
MAX_LOGIN_ATTEMPTS=3
BRUTE_FORCE_WINDOW=120

# Règle 4 : Exfiltration
MASS_ACCESS_LIMIT=20
MASS_ACCESS_WINDOW=60

# Règle 5 : Énumération
ENUM_USERNAMES_LIMIT=3
ENUM_WINDOW=300

# Règle 6 : Horaires
ALLOWED_HOURS_START=7
ALLOWED_HOURS_END=20

# Logs
LOG_FILE_PATH=logs/security.log
LOG_MAX_BYTES=5242880
LOG_BACKUP_COUNT=3

# WebSocket
WS_HEARTBEAT_INTERVAL=30
```

### 17.4 Déploiement cloud (Railway)

1. **Créer un projet Railway** avec PostgreSQL
2. **Obtenir DATABASE_URL** depuis le dashboard Railway
3. **Configurer les variables** dans Railway Dashboard
4. **Déployer** :
   ```bash
   # Railway CLI
   railway init
   railway up
   ```
5. **Initialiser la BDD** :
   ```bash
   psql $DATABASE_URL < init_db.sql
   psql $DATABASE_URL < seed_data.sql
   ```

L'application est accessible sur `https://xud-bank-production.up.railway.app`

### 17.5 Structure de production

- **Serveur ASGI** : Uvicorn avec workers multiples
- **Process Manager** : Gunicorn (optionnel, pour prod)
- **Logs** : Rotation automatique (5MB × 3)
- **HTTPS** : Géré par Railway (Let's Encrypt)

---

## 18. Tests des règles de détection

### 18.1 Test 1 : Brute Force (Règle 1)

**Objectif** : Verrouiller un compte après 3 échecs

```bash
# 3 tentatives échouées en < 2 min
curl -X POST http://localhost:8000/auth/login \
  -d "email=soc@xud-bank.com&password=WrongPass1" \
  -c cookies.txt

curl -X POST http://localhost:8000/auth/login \
  -d "email=soc@xud-bank.com&password=WrongPass2" \
  -c cookies.txt

curl -X POST http://localhost:8000/auth/login \
  -d "email=soc@xud-bank.com&password=WrongPass3" \
  -c cookies.txt
```

**Résultat attendu** :
- ✅ Compte verrouillé (`is_locked = TRUE`)
- ✅ Alerte MEDIUM créée
- ✅ Événement `LOGIN_LOCKED` généré

**Vérification SQL** :
```sql
SELECT is_locked FROM users WHERE email = 'soc@xud-bank.com';
-- Doit retourner TRUE

SELECT * FROM alerts WHERE alert_level = 'MEDIUM' 
ORDER BY timestamp DESC LIMIT 1;
```

---

### 18.2 Test 2 : Injection SQL (Règle 2)

**Objectif** : Détecter un pattern SQL injection

```bash
# Injection dans le formulaire de login
curl -X POST http://localhost:8000/auth/login \
  -d "email=' OR 1=1 --&password=test" \
  -c cookies.txt
```

**Résultat attendu** :
- ✅ Rejetée avec HTTP 400
- ✅ Alerte HIGH créée
- ✅ Payload enregistré

**Vérification SQL** :
```sql
SELECT * FROM security_events 
WHERE event_type = 'SQL_INJECTION' 
ORDER BY timestamp DESC LIMIT 1;
```

---

### 18.3 Test 3 : Accès Admin non autorisé (Règle 3)

**Objectif** : Tenter d'accéder à /admin avec un rôle non-admin

```bash
# Login avec utilisateur standard
curl -X POST http://localhost:8000/auth/login \
  -d "email=dupont@mail.com&password=Dupont@1234" \
  -c cookies.txt

# Tentative d'accès admin
curl http://localhost:8000/admin/dashboard \
  -b cookies.txt
```

**Résultat attendu** :
- ✅ HTTP 403 Forbidden
- ✅ Alerte HIGH créée
- ✅ Événement `UNAUTHORIZED_ACCESS` généré

---

### 18.4 Test 4 : Exfiltration massive (Règle 4)

**Objectif** : >20 accès aux données en 1 minute

```bash
# Login
curl -X POST http://localhost:8000/auth/login \
  -d "email=hor@xud-bank.com&password=Hor@1234" \
  -c cookies.txt

# 25 requêtes rapides
for i in {1..25}; do
  curl http://localhost:8000/data/accounts -b cookies.txt &
done
wait
```

**Résultat attendu** :
- ✅ Alerte CRITICAL après le 20ème accès
- ✅ Notification WebSocket envoyée

---

### 18.5 Test 5 : Énumération (Règle 5)

**Objectif** : 3 usernames différents depuis la même IP

```bash
# 3 tentatives avec emails différents
curl -X POST http://localhost:8000/auth/login \
  -d "email=soc@xud-bank.com&password=wrong" \
  -c cookies.txt

curl -X POST http://localhost:8000/auth/login \
  -d "email=hor@xud-bank.com&password=wrong" \
  -c cookies.txt

curl -X POST http://localhost:8000/auth/login \
  -d "email=directeur@xud-bank.com&password=wrong" \
  -c cookies.txt
```

**Résultat attendu** :
- ✅ Alerte MEDIUM créée
- ✅ IP flaggée comme suspecte

---

### 18.6 Test 6 : Accès hors horaires (Règle 6)

**Objectif** : Se connecter entre 20h et 07h UTC

```bash
# Modifier temporairement ALLOWED_HOURS_END=20 dans .env
# Ou tester tard le soir

curl -X POST http://localhost:8000/auth/login \
  -d "email=pierre@mail.com&password=Pierre@1234" \
  -c cookies.txt
```

**Résultat attendu** :
- ✅ Connexion réussie
- ✅ Alerte LOW créée
- ✅ Heure enregistrée

---

### 18.7 Test 7 : URL suspecte

**Objectif** : Tenter un path traversal

```bash
curl "http://localhost:8000/../../../etc/passwd"
curl "http://localhost:8000/.env"
```

**Résultat attendu** :
- ✅ HTTP 403 Forbidden
- ✅ Alerte HIGH créée
- ✅ URL enregistrée

---

### 18.8 Monitoring des tests

**Voir les derniers événements** :
```sql
SELECT event_type, severity, username, ip_address, description, timestamp
FROM security_events
ORDER BY timestamp DESC
LIMIT 10;
```

**Voir les alertes non résolues** :
```sql
SELECT alert_level, message, timestamp
FROM alerts
WHERE resolved = FALSE
ORDER BY timestamp DESC;
```

**Statistiques par type** :
```sql
SELECT event_type, COUNT(*) as count
FROM security_events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY event_type
ORDER BY count DESC;
```

---

## Conclusion

**XUD-Bank SecureDataMonitor** est une application bancaire de démonstration qui illustre les meilleures pratiques en matière de :

- ✅ **Architecture asynchrone** (FastAPI + asyncio + asyncpg)
- ✅ **Sécurité defensive** (bcrypt, sessions signées, headers HTTP)
- ✅ **Détection d'intrusion** (6 règles SOC proactives)
- ✅ **Temps réel** (WebSocket avec batching haute performance)
- ✅ **Traçabilité** (double journalisation fichier + BDD)
- ✅ **Scalabilité** (Pub/Sub découplé, threadpool, caching)

Ce projet universitaire démontre la maîtrise des concepts avancés de programmation événementielle, de cybersécurité, et de développement Web moderne.

---

> **Document réalisé par le département FAST-LPSIC M2**  
> Université de Kara – Session 2025-2026  
> *Programmation Événementielle & Cybersécurité*
