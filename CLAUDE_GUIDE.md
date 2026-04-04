# XUD-Bank — Guide Technique Complet pour CLAUDE

> **Document de référence technique** - Architecture, modèles, routes, services et moteur de surveillance  
> Dernière mise à jour : Avril 2026

---

## 📋 Table des Matières

1. [Vue d'Ensemble](#1-vue-densemble)
2. [Application Bancaire (app/)](#2-application-bancaire-app)
3. [Base de Données & Modèles](#3-base-de-données--modèles)
4. [Routes & Contrôleurs](#4-routes--contrôleurs)
5. [Services Métier](#5-services-métier)
6. [Templates & Frontend](#6-templates--frontend)
7. [Module de Surveillance (secureDataMonitor/)](#7-module-de-surveillance-securedatamonitor)
8. [Système Événementiel](#8-système-événementiel)
9. [Règles de Détection](#9-règles-de-détection)
10. [Flux de Données](#10-flux-de-données)

---

## 1. Vue d'Ensemble

### Architecture Générale

XUD-Bank est une application bancaire FastAPI avec un moteur de surveillance intégré (SecureDataMonitor). L'architecture suit le pattern **Layered Architecture** avec séparation stricte des responsabilités.

```
┌─────────────────────────────────────────────┐
│  PRÉSENTATION    routers/ + templates/      │  HTTP, HTML, WebSocket
├─────────────────────────────────────────────┤
│  MÉTIER          services/                  │  Auth, Reports, Threadpool
├─────────────────────────────────────────────┤
│  ÉVÉNEMENTIELLE  secureDataMonitor/events/  │  Pub/Sub, Handlers
├─────────────────────────────────────────────┤
│  PERSISTANCE     models/ + database.py      │  SQLAlchemy 2.0 async
└─────────────────────────────────────────────┘
```

### Technologies Clés

- **Backend**: FastAPI (Python 3.13+)
- **Base de données**: PostgreSQL avec asyncpg
- **ORM**: SQLAlchemy 2.0 (async)
- **Sessions**: itsdangerous (cookies signés)
- **PDF**: FPDF2
- **WebSocket**: Natif FastAPI
- **Frontend**: HTML5 + Vanilla CSS/JS + Chart.js

### Séparation des Tâches (Segregation of Duties)

Le système implémente 4 rôles strictement séparés :

| Rôle | Espace | Responsabilités | Accès Rapports |
|------|--------|----------------|----------------|
| `soc` | `/soc/*` | Surveillance, verrouillage comptes, logs, alerts, events | ❌ Aucun |
| `directeur` | `/direction/*` | Recrutement/radiation personnel, vision complète comptes | ✅ PUBLIC+CONFIDENTIEL+SECRET |
| `comptable` | `/comptabilite/*` | Création comptes bancaires, gestion virements | ✅ PUBLIC+CONFIDENTIEL |
| `utilisateur` | `/client/*` | Consultation soldes, virements personnels | ❌ Aucun |

---

## 2. Application Bancaire (app/)

### Structure

```
app/
├── main.py                    # Point d'entrée, montage routers, middlewares
├── database.py                # Configuration BDD (Railway + asyncpg)
├── config.py                  # Settings Pydantic + Jinja2 environment
├── models/                    # Schémas SQLAlchemy
├── routers/                   # Contrôleurs par rôle
├── services/                  # Logique métier
├── templates/                 # Templates Jinja2 par rôle
└── static/css/                # Styles CSS globaux
```

### Fichiers Principaux

#### `main.py` - Point d'Entrée

**Responsabilités :**
- Configuration FastAPI app
- Montage des routers (`auth`, `soc`, `direction`, `comptabilite`, `client`)
- Montage du module SecureDataMonitor
- Middleware de session (SessionMiddleware)
- Gestionnaires d'exceptions globaux (403, 404, 500)
- Intégration des règles de détection dans les handlers d'erreurs

**Code clé :**
```python
app = FastAPI(title="XUD-Bank")

# Montage des routers
app.include_router(auth.router, prefix="/auth", tags=["Authentification"])
app.include_router(soc.router, prefix="/soc", tags=["SOC"])
app.include_router(direction.router, prefix="/direction", tags=["Direction"])
app.include_router(comptabilite.router, prefix="/comptabilite", tags=["Comptabilité"])
app.include_router(client.router, prefix="/client", tags=["Client"])

# Montage SecureDataMonitor
app.mount("/secureDataMonitor", sdm_app)

# Middleware session
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

# Exception handler 403 avec Règle 7
@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    # Vérification Règle 7 : vol dossiers bancaires
    if check_unauthorized_report_access(request.url.path, role):
        await dispatcher.emit("bank_fraud_attempt", {...})
```

#### `database.py` - Configuration Base de Données

**Responsabilités :**
- Configuration URL BDD depuis `.env`
- Création engine async avec asyncpg
- Session factory asynchrone
- Fonction utilitaire `get_db()` pour dependency injection

**Code clé :**
```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
```

#### `config.py` - Configuration

**Responsabilités :**
- Settings Pydantic avec validation `.env`
- Configuration Jinja2 Environment avec cache bytecode
- Variables : DATABASE_URL, SECRET_KEY, paramètres détection

---

## 3. Base de Données & Modèles

### Schéma Global

La base de données contient **5 tables principales** avec relations et index optimisés.

### Tables Détaillées

#### 1. `users` - Utilisateurs du Système

**Fichier :** `app/models/user.py`

**Colonnes :**
```python
id              UUID            PRIMARY KEY
username        VARCHAR(50)     UNIQUE, NOT NULL
email           VARCHAR(100)    UNIQUE, NOT NULL
password_hash   VARCHAR(255)    NOT NULL (bcrypt)
role            ENUM            soc|directeur|comptable|utilisateur
is_locked       BOOLEAN         DEFAULT FALSE
failed_attempts INTEGER         DEFAULT 0
last_failed_at  TIMESTAMP       NULLABLE
created_at      TIMESTAMP       DEFAULT NOW()
```

**Enum UserRole :**
```python
class UserRole(str, enum.Enum):
    SOC = "soc"
    DIRECTEUR = "directeur"
    COMPTABLE = "comptable"
    UTILISATEUR = "utilisateur"
```

**Relations :**
- One-to-Many avec `bank_accounts` (via `owner_id`)
- One-to-Many avec `security_events` (via `username`)

**Méthodes importantes :**
```python
def verify_password(self, plain_password: str) -> bool:
    """Vérifie mot de passe avec bcrypt"""
    
def increment_failed_attempts(self):
    """Incrémente compteur échecs et met à jour timestamp"""
    
def reset_failed_attempts(self):
    """Réinitialise après connexion réussie"""
```

---

#### 2. `bank_accounts` - Comptes Bancaires

**Fichier :** `app/models/bank_account.py`

**Colonnes :**
```python
id              UUID            PRIMARY KEY
id_compte       VARCHAR(20)     UNIQUE, NOT NULL (ex: FR76...)
titulaire       VARCHAR(100)    NOT NULL
solde           DECIMAL(15,2)   DEFAULT 0.00
historique      TEXT            JSON sérialisé des transactions
classification  ENUM            public|confidentiel|secret
owner_id        UUID            FK → users.id
created_at      TIMESTAMP       DEFAULT NOW()
```

**Enum AccountClassification :**
```python
class AccountClassification(str, enum.Enum):
    PUBLIC = "public"
    CONFIDENTIEL = "confidentiel"
    SECRET = "secret"
```

**Structure JSON historique :**
```json
{
  "transactions": [
    {
      "date": "2026-04-03T10:30:00",
      "type": "credit|debit",
      "montant": 50000,
      "description": "Virement reçu",
      "balance_after": 150000
    }
  ]
}
```

**Relations :**
- Many-to-One avec `users` (via `owner_id`)

**Méthodes importantes :**
```python
def add_transaction(self, transaction_type: str, amount: float, description: str):
    """Ajoute transaction au historique JSON et met à jour solde"""
    
def to_dict(self) -> dict:
    """Sérialise en dictionnaire pour templates"""
```

---

#### 3. `security_events` - Journal de Sécurité

**Fichier :** `app/models/security_event.py`

**Colonnes :**
```python
id              UUID            PRIMARY KEY
timestamp       TIMESTAMP       DEFAULT NOW()
username        VARCHAR(50)     NULLABLE
ip_address      INET            NOT NULL
event_type      ENUM            13 types (voir ci-dessous)
severity        ENUM            LOW|MEDIUM|HIGH|CRITICAL
description     TEXT            NOT NULL
status          ENUM            open|investigating|closed
action_taken    TEXT            NULLABLE
```

**Enum EventType (13 types) :**
```python
class EventType(str, enum.Enum):
    LOGIN_SUCCESS        = "LOGIN_SUCCESS"
    LOGIN_FAILED         = "LOGIN_FAILED"
    LOGIN_LOCKED         = "LOGIN_LOCKED"
    UNKNOWN_USER         = "UNKNOWN_USER"
    UNAUTHORIZED_ACCESS  = "UNAUTHORIZED_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    SQL_INJECTION        = "SQL_INJECTION"
    RATE_LIMIT           = "RATE_LIMIT"
    MASS_DATA_ACCESS     = "MASS_DATA_ACCESS"
    ENUM_ATTEMPT         = "ENUM_ATTEMPT"
    OFF_HOURS_ACCESS     = "OFF_HOURS_ACCESS"
    SUSPICIOUS_URL       = "SUSPICIOUS_URL"
    BANK_FRAUD_ATTEMPT   = "BANK_FRAUD_ATTEMPT"  # Règle 7
```

**Enum SeverityLevel :**
```python
class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
```

**Enum EventStatus :**
```python
class EventStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"
```

**Index Performance :**
- `idx_security_events_type` - Filtrage par type
- `idx_security_events_severity` - Filtrage par sévérité
- `idx_security_events_timestamp` - Tris chronologiques

---

#### 4. `alerts` - Alertes Générées

**Fichier :** `app/models/alert.py`

**Colonnes :**
```python
id              UUID            PRIMARY KEY
timestamp       TIMESTAMP       DEFAULT NOW()
alert_level     ENUM            LOW|MEDIUM|HIGH|CRITICAL
source_event_id UUID            FK → security_events.id
message         TEXT            NOT NULL
resolved        BOOLEAN         DEFAULT FALSE
```

**Relations :**
- Many-to-One avec `security_events` (via `source_event_id`)

**Index :**
- `idx_alerts_unresolved` - WHERE resolved = FALSE
- `idx_alerts_level` - Filtrage par niveau

---

#### 5. `login_attempts` - Tentatives de Connexion

**Fichier :** `app/models/login_attempt.py`

**Colonnes :**
```python
id              UUID            PRIMARY KEY
ip_address      INET            NOT NULL
username_tried  VARCHAR(50)     NOT NULL
timestamp       TIMESTAMP       DEFAULT NOW()
success         BOOLEAN         NOT NULL
```

**Index Performance :**
- `idx_login_attempts_username_time` - Détection brute force
- `idx_login_attempts_ip_time` - Détection énumération

---

### Scripts SQL

#### `init_db.sql` - Initialisation Schema

**Contenu :**
1. Création types ENUM (user_role, account_classification, event_type, severity_level, event_status)
2. Création table `users` avec contraintes
3. Création table `bank_accounts` avec FK
4. Création table `security_events`
5. Création table `alerts` avec FK
6. Création table `login_attempts`
7. Création index performance

**Commande :**
```bash
psql $DATABASE_URL < init_db.sql
```

#### `seed_data.sql` - Données Démo

**Contenu :**
1. Insertion 4 utilisateurs (soc, directeur, comptable, utilisateur)
2. Insertion 16 comptes bancaires répartis (PUBLIC/CONFIDENTIEL/SECRET)
3. Historique transactions JSON pour chaque compte

**Commande :**
```bash
psql $DATABASE_URL < seed_data.sql
```

---

## 4. Routes & Contrôleurs

### Architecture des Routers

Chaque router est un module FastAPI indépendant avec :
- Préfixe de route
- Tags OpenAPI
- Dépendances RBAC (`require_role()`)
- Templates dédiés

---

### 4.1 Router Authentification (`app/routers/auth.py`)

**Préfixe :** `/auth`  
**Accès :** Public (sauf logout)

**Routes :**

#### `GET /auth/login`
- **Description :** Page de connexion
- **Template :** `login.html`
- **Logique :** Redirige vers dashboard si déjà authentifié

#### `POST /auth/login`
- **Description :** Traitement authentification
- **Paramètres :** Form data (email, password)
- **Logique :**
  1. Recherche user par email
  2. Vérifie mot de passe (bcrypt via threadpool)
  3. Vérifie si compte verrouillé
  4. Incrémente échecs ou réinitialise
  5. Crée session signée
  6. Émet événement `login_success` ou `login_failed`
  7. Redirige selon rôle vers espace dédié

**Redirections post-login :**
```python
role_routes = {
    "soc": "/soc/dashboard",
    "directeur": "/direction/dashboard",
    "comptable": "/comptabilite/dashboard",
    "utilisateur": "/client/dashboard"
}
```

#### `GET /auth/logout`
- **Description :** Déconnexion
- **Logique :** Supprime cookie session, redirige vers login

#### `GET /auth/register` & `POST /auth/register`
- **Statut :** DÉSACTIVÉ (404 Not Found)
- **Raison :** Inscription uniquement par Direction

---

### 4.2 Router SOC (`app/routers/soc.py`)

**Préfixe :** `/soc`  
**Accès :** `require_role("soc")`

**Routes :**

#### `GET /soc/dashboard`
- **Description :** Dashboard sécurité temps réel
- **Template :** `soc/dashboard.html`
- **Données :** Stats événements, graphiques Chart.js, alertes actives
- **WebSocket :** Connexion automatique à `/ws/alerts`

#### `GET /soc/users`
- **Description :** Liste tous utilisateurs avec actions
- **Template :** `soc/users.html`
- **Actions :** Verrouiller/déverrouiller comptes
- **Affichage :** Username, rôle, statut verrouillage, tentatives échouées

#### `POST /soc/users/{id}/lock`
- **Description :** Verrouille compte utilisateur
- **Logique :** Set `is_locked = TRUE`, émet événement `account_locked`

#### `POST /soc/users/{id}/unlock`
- **Description :** Déverrouille compte utilisateur
- **Logique :** Set `is_locked = FALSE`, reset failed_attempts

#### `GET /soc/alerts`
- **Description :** Gestion alertes (actives/résolues)
- **Template :** `soc/alerts.html`
- **Filtres :** Par niveau, par statut
- **Action :** Résoudre alerte manuellement

#### `POST /soc/alerts/{id}/resolve`
- **Description :** Marque alerte comme résolue
- **Logique :** Set `resolved = TRUE`

#### `GET /soc/events`
- **Description :** Historique complet événements sécurité
- **Template :** `soc/events.html`
- **Filtres :** Par type, sévérité, date range
- **Tri :** Chronologique inversé

#### `GET /soc/logs/raw`
- **Description :** Affiche contenu brut de `logs/security.log`
- **Template :** `soc/logs.html`
- **Usage :** Analyse judiciaire, debugging

#### `GET /soc/clear-data`
- **Description :** Page confirmation suppression données
- **Template :** `soc/clear_data.html`
- **Avertissement :** Double confirmation requise

#### `POST /soc/clear-data`
- **Description :** Supprime toutes alerts + security_events
- **Logique :** DELETE FROM alerts, DELETE FROM security_events
- **Sécurité :** Confirmation explicite requise

---

### 4.3 Router Direction (`app/routers/direction.py`)

**Préfixe :** `/direction`  
**Accès :** `require_role("directeur")`

**Routes :**

#### `GET /direction/dashboard`
- **Description :** Dashboard direction avec stats sécurité
- **Template :** `direction/dashboard.html`
- **Données :** Stats globales, graphiques, derniers événements
- **Note :** Pas d'accès aux détails alerts/events (réservé SOC)

#### `GET /direction/users`
- **Description :** Gestion personnel (SOC, directeurs, comptables)
- **Template :** `direction/users.html`
- **Différence SOC :** Ne montre pas les utilisateurs lambda
- **Actions :** Voir détails, radiate personnel

#### `GET /direction/users/new`
- **Description :** Formulaire recrutement nouveau personnel
- **Template :** `direction/new_user.html`
- **Champs :** Username, email, password, rôle (soc/directeur/comptable)

#### `POST /direction/users/new`
- **Description :** Crée nouveau compte personnel
- **Validation :** Username/email unique, password fort
- **Logique :** Hash password bcrypt, insert DB, redirect users

#### `POST /direction/users/{id}/delete`
- **Description :** Radie membre personnel (suppression physique)
- **Sécurité :** Empêche auto-suppression
- **Logique :** DELETE FROM users WHERE id = :id

#### `GET /direction/accounts`
- **Description :** Vision complète TOUS comptes bancaires
- **Template :** `direction/accounts.html`
- **Contenu :** PUBLIC + CONFIDENTIEL + SECRET
- **Affichage :** Cartes avec classification colorée, statistiques

#### `GET /direction/rapport`
- **Description :** Génère rapport PDF détaillé tous comptes
- **Format :** PDF inline (ouverture navigateur)
- **Contenu :**
  - En-tête avec date/générateur
  - Statistiques globales
  - Section PUBLIC (vert) avec sous-total
  - Section CONFIDENTIEL (orange) avec sous-total
  - Section SECRET (rouge) avec sous-total
  - Détails complets : ID, titulaire, solde, dates création/MAJ
- **Technologie :** FPDF2 avec ASCII-only (pas d'emojis)
- **Nom fichier :** `rapport_complets_YYYYMMDD_HHMM.pdf`

**Logique génération PDF :**
```python
pdf = FPDF()
pdf.add_page()
pdf.set_font("helvetica", "B", 16)

# Header
pdf.cell(0, 12, "XUD-BANK - RAPPORT DETAILLE DES COMPTES", ln=True, align="C")

# Stats globales
pdf.cell(95, 8, f"Total Global: {total_global:,.2f} XOF", border=1)

# Sections par classification
for classification in ["public", "confidentiel", "secret"]:
    # Header coloré
    pdf.set_fill_color(R, G, B)  # Vert/Orange/Rouge
    pdf.cell(0, 10, f"[{classification.upper()}] COMPTES ...", ln=True, fill=True)
    
    # Tableau comptes
    for account in accounts[classification]:
        pdf.cell(40, 8, account.id_compte, border=1)
        pdf.cell(60, 8, account.titulaire, border=1)
        pdf.cell(50, 8, f"{account.solde:,.2f}", border=1)

return Response(content=bytes(pdf.output()), media_type="application/pdf")
```

---

### 4.4 Router Comptabilité (`app/routers/comptabilite.py`)

**Préfixe :** `/comptabilite`  
**Accès :** `require_role("comptable")` OU `require_role("directeur")`

**Routes :**

#### `GET /comptabilite/dashboard`
- **Description :** Dashboard gestion bancaire
- **Template :** `comptabilite/dashboard.html`
- **Contenu :** Liste comptes PUBLIC + CONFIDENTIEL (pas SECRET)
- **Actions :** Créer nouveau compte
- **Design :** Cartes identiques à direction/accounts.html

#### `POST /comptabilite/accounts/create`
- **Description :** Crée nouveau compte bancaire
- **Paramètres :** id_compte, titulaire, solde_initial, classification, owner_id
- **Validation :** id_compte unique, classification valide
- **Logique :** Insert DB, redirect dashboard

#### `GET /comptabilite/rapport`
- **Description :** Rapport PDF comptes PUBLIC + CONFIDENTIEL
- **Différence direction :** PAS de section SECRET
- **Titre :** "RAPPORT DES COMPTES - COMPTABILITE"
- **Mention :** "Accès : PUBLIC + CONFIDENTIEL"
- **Structure :** Identique à rapport direction mais 2 sections seulement

---

### 4.5 Router Client (`app/routers/client.py`)

**Préfixe :** `/client`  
**Accès :** `require_role("utilisateur")`

**Routes :**

#### `GET /client/dashboard`
- **Description :** Dashboard client personnel
- **Template :** `client/dashboard.html`
- **Contenu :**
  - Liste comptes du client (filtré par owner_id)
  - Solde actuel
  - Dernières transactions (depuis historique JSON)
  - Formulaire virement

#### `POST /client/transfers`
- **Description :** Effectue virement entre comptes
- **Validation :**
  - Solde suffisant
  - Compte destination existe
  - Montant > 0
- **Logique :**
  1. Débite compte source
  2. Crédite compte destination
  3. Ajoute entrée dans historique JSON des deux comptes
  4. Commit transaction
- **Sécurité :** Transaction atomique (rollback si erreur)

---

## 5. Services Métier

### 5.1 Auth Service (`app/services/auth_service.py`)

**Responsabilités :**
- Authentification utilisateurs
- Création nouveaux comptes
- Hachage mots de passe (bcrypt via threadpool)
- Contrôle d'accès RBAC

**Fonctions Clés :**

#### `authenticate_user(db, email, password)`
```python
async def authenticate_user(db: AsyncSession, email: str, password: str):
    """
    Authentifie utilisateur avec vérifications sécurité
    
    Retourne: User ou None
    Actions:
    - Recherche par email
    - Vérifie is_locked
    - Vérifie password (bcrypt via run_in_threadpool)
    - Incrémente/réinitialise failed_attempts
    - Log login_attempts
    """
```

#### `create_user(db, username, email, password, role)`
```python
async def create_user(db: AsyncSession, username: str, email: str, 
                     password: str, role: str):
    """
    Crée nouvel utilisateur
    
    Validation:
    - Username unique
    - Email unique
    - Role valide
    - Password fort
    
    Actions:
    - Hash password bcrypt
    - Insert DB
    - Return User
    """
```

#### `require_role(required_role)`
```python
def require_role(required_role: str):
    """
    Décorateur dépendance FastAPI pour RBAC
    
    Usage:
    @router.get("/protected")
    async def protected(user: dict = Depends(require_role("soc"))):
        ...
    
    Logique:
    - Extrait session cookie
    - Vérifie role == required_role
    - 403 si non autorisé
    - Return dict {username, role, user_id}
    """
```

**Threadpool pour Bcrypt :**
```python
from fastapi.concurrency import run_in_threadpool

# Bcrypt est bloquant, exécuté sur threadpool
password_valid = await run_in_threadpool(
    user.verify_password, plain_password
)
```

---

### 5.2 Report Service (`app/services/report_service.py`)

**Statut :** Legacy (remplacé par génération PDF inline dans routers)

**Historique :** Ancienne méthode de génération rapports HTML  
**Remplacé par :** FPDF2 dans `direction.py` et `comptabilite.py`

---

## 6. Templates & Frontend

### Architecture Templates

```
templates/
├── base.html                  # Template parent commun
├── login.html                 # Page connexion
├── register.html              # Page inscription (inutilisée)
├── errors/                    # Pages erreur
│   ├── 401.html
│   ├── 403.html
│   ├── 404.html
│   └── 500.html
├── soc/                       # Templates SOC
│   ├── dashboard.html
│   ├── users.html
│   ├── alerts.html
│   ├── events.html
│   ├── logs.html
│   └── clear_data.html
├── direction/                 # Templates Direction
│   ├── dashboard.html
│   ├── users.html
│   ├── new_user.html
│   └── accounts.html
├── comptabilite/              # Templates Comptabilité
│   └── dashboard.html
└── client/                    # Templates Client
    └── dashboard.html
```

### Template Base (`base.html`)

**Structure :**
```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>{% block title %}XUD-Bank{% endblock %}</title>
    <link rel="stylesheet" href="/static/css/base.css">
    {% block extra_css %}{% endblock %}
</head>
<body>
    <!-- Navigation conditionnelle selon rôle -->
    <nav class="sidebar">
        {% if user_role == 'soc' %}
            <!-- Menu SOC -->
        {% elif user_role == 'directeur' %}
            <!-- Menu Direction -->
        {% endif %}
    </nav>
    
    <!-- Contenu principal -->
    <main>
        {% block content %}{% endblock %}
    </main>
    
    {% block scripts %}{% endblock %}
</body>
</html>
```

**Features :**
- Héritage Jinja2 (`{% extends "base.html" %}`)
- Blocks : title, content, extra_css, scripts
- Navigation dynamique selon `user_role`
- Flash messages support
- CSRF tokens

---

### Design System CSS

**Fichier :** `app/static/css/base.css`

**Variables CSS :**
```css
:root {
    --bg-dark: #0a0e17;
    --bg-glass: rgba(15, 23, 42, 0.6);
    --primary: #3b82f6;
    --s-low: #10b981;      /* Vert - LOW */
    --s-med: #f59e0b;      /* Orange - MEDIUM */
    --s-hi: #ef4444;       /* Rouge - HIGH */
    --s-critical: #dc2626; /* Rouge foncé - CRITICAL */
    --bdr2: rgba(148, 163, 184, 0.2);
    --sh-card: 0 4px 6px rgba(0, 0, 0, 0.3);
}
```

**Composants Réutilisables :**
- `.acc-grid` - Grid responsive cartes comptes
- `.acc-card` - Carte compte bancaire
- `.classification-badge` - Badge classification coloré
- `.stat-card` - Carte statistique dashboard
- `.btn-primary`, `.btn-danger` - Boutons standardisés

---

### JavaScript WebSocket (`secureDataMonitor/static/js/ws_alerts.js`)

**Responsabilités :**
- Connexion WebSocket à `/ws/alerts`
- Reconnexion automatique (backoff exponentiel)
- Batching affichage via `requestAnimationFrame`
- Mise à jour temps réel dashboard SOC

**Architecture :**
```javascript
class AlertWebSocket {
    constructor() {
        this.ws = null;
        this.reconnectAttempts = 0;
        this.alertBuffer = [];
        this.isUpdating = false;
    }
    
    connect() {
        this.ws = new WebSocket('ws://localhost:8000/ws/alerts');
        this.ws.onmessage = (event) => {
            const alert = JSON.parse(event.data);
            this.alertBuffer.push(alert);
            this.scheduleUpdate();
        };
    }
    
    scheduleUpdate() {
        if (!this.isUpdating) {
            this.isUpdating = true;
            requestAnimationFrame(() => {
                this.flushBuffer();
                this.isUpdating = false;
            });
        }
    }
    
    flushBuffer() {
        // Affiche tous les alerts en buffer
        // DOM updates batchées pour performance
    }
}
```

**Optimisation Performance :**
- Batching via `requestAnimationFrame` (60fps max)
- Buffer accumulation pendant rendering
- Reconnexion backoff : 1s, 2s, 4s, 8s... (max 30s)

---

## 7. Module de Surveillance (secureDataMonitor/)

### Architecture

```
secureDataMonitor/
├── __init__.py                # Création sub-app FastAPI
├── events/                    # Système événementiel Pub/Sub
│   ├── dispatcher.py          # EventDispatcher central
│   └── handlers.py            # Handlers pour chaque événement
├── services/                  # Détection & journalisation
│   ├── detection.py           # 7 règles de détection
│   └── logger.py              # Logger événements + alertes
├── routers/                   # API REST & WebSockets
│   ├── api_alerts.py          # WebSocket broadcast + stats
│   └── admin.py               # Routes admin legacy
├── static/js/                 # Client WebSocket
│   └── ws_alerts.js
└── templates/                 # Templates legacy
    └── errors/
```

### Mounting dans App Principale

Dans `app/main.py` :
```python
from secureDataMonitor import app as sdm_app
app.mount("/secureDataMonitor", sdm_app)
```

**Résultat :** Toutes routes SDM préfixées par `/secureDataMonitor`

---

## 8. Système Événementiel

### Pattern Pub/Sub

Le système utilise un **EventDispatcher** asynchrone pour découpler détection et réaction.

**Flux :**
```
Router détecte incident
    ↓
dispatcher.emit("event_type", data)
    ↓
Dispatcher notifie tous handlers abonnés
    ↓
Handlers exécutent en parallèle :
  - Logger événement BDD
  - Créer alerte si nécessaire
  - Broadcast WebSocket
  - Actions automatiques (verrouillage)
```

---

### 8.1 Event Dispatcher (`secureDataMonitor/events/dispatcher.py`)

**Classe :** `EventDispatcher`

**Responsabilités :**
- Registry handlers par type d'événement
- Émission événements asynchrones
- Exécution parallèle handlers
- Error handling isolé (un handler crash n'affecte pas autres)

**Code :**
```python
class EventDispatcher:
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
    
    def on(self, event_type: str, handler: Callable):
        """Abonne handler à type d'événement"""
        self._handlers[event_type].append(handler)
    
    async def emit(self, event_type: str, data: dict):
        """Émet événement à tous handlers abonnés"""
        tasks = []
        for handler in self._handlers.get(event_type, []):
            try:
                tasks.append(handler(data))
            except Exception as e:
                log.error(f"Handler error: {e}")
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

# Instance globale
dispatcher = EventDispatcher()
```

**Registration Handlers :**
```python
# Dans handlers.py ou init
dispatcher.on("login_failed", handle_failed_login)
dispatcher.on("bank_fraud_attempt", handle_bank_fraud_attempt)
dispatcher.on("mass_data_access", handle_mass_access)
# ... etc
```

---

### 8.2 Event Handlers (`secureDataMonitor/events/handlers.py`)

Chaque handler est une fonction async qui traite un type d'événement spécifique.

#### Handler Types

**1. `handle_login_success(data)`**
- Sévérité : LOW
- Action : Log événement LOGIN_SUCCESS
- Pas d'alerte créée

**2. `handle_failed_login(data)`**
- Sévérité : MEDIUM
- Actions :
  - Log LOGIN_FAILED
  - Vérifie Règle 1 (brute force)
  - Si 3 échecs < 2min → lock account + alerte MEDIUM

**3. `handle_account_locked(data)`**
- Sévérité : MEDIUM
- Action : Log LOGIN_LOCKED + alerte MEDIUM

**4. `handle_unknown_user(data)`**
- Sévérité : MEDIUM
- Action : Log UNKNOWN_USER + alerte MEDIUM

**5. `handle_unauthorized(data)`**
- Sévérité : HIGH
- Action : Log UNAUTHORIZED_ACCESS + alerte HIGH

**6. `handle_privilege_escalation(data)`**
- Sévérité : HIGH
- Action : Log PRIVILEGE_ESCALATION + alerte HIGH

**7. `handle_rate_limit(data)`**
- Sévérité : MEDIUM
- Action : Log RATE_LIMIT + alerte MEDIUM

**8. `handle_mass_access(data)`**
- Sévérité : CRITICAL
- Action : Log MASS_DATA_ACCESS + alerte CRITICAL

**9. `handle_off_hours(data)`**
- Sévérité : LOW
- Action : Log OFF_HOURS_ACCESS (pas d'alerte)

**10. `handle_sql_injection(data)`**
- Sévérité : HIGH
- Action : Log SQL_INJECTION + alerte HIGH + payload dans description

**11. `handle_enum_attempt(data)`**
- Sévérité : MEDIUM
- Action : Log ENUM_ATTEMPT + alerte MEDIUM

**12. `handle_suspicious_url(data)`**
- Sévérité : HIGH
- Action : Log SUSPICIOUS_URL + alerte HIGH

**13. `handle_bank_fraud_attempt(data)`** ⭐ **RÈGLE 7**
- Sévérité : **CRITICAL**
- Actions :
  - Log BANK_FRAUD_ATTEMPT
  - Crée alerte CRITICAL avec message explicite
  - Broadcast WebSocket immédiat
  - Log critique dans security.log

**Code Handle Bank Fraud :**
```python
async def handle_bank_fraud_attempt(data: dict) -> None:
    """
    Règle 7 : Accès non autorisé aux rapports bancaires → CRITICAL
    """
    async with AsyncSessionLocal() as db:
        # Log événement
        event = await sec_logger.log_event(
            db=db,
            event_type=EventType.BANK_FRAUD_ATTEMPT,
            severity=SeverityLevel.CRITICAL,
            username=data.get("username"),
            ip_address=data["ip"],
            description=f"Tentative de vol de dossiers bancaires : rôle='{data.get('role')}' sur {data.get('path')}",
            action_taken="Accès refusé et journalisé - ALERTE MAXIMUM",
        )
        await broadcast_event(event)
        
        # Crée alerte CRITICAL
        alert = await sec_logger.create_alert(
            db=db,
            level=SeverityLevel.CRITICAL,
            source_event_id=event.id,
            message=f"🚨⚠️ VOL DE DOSSIERS BANCAIRES : Utilisateur '{data.get('username')}' (rôle: {data.get('role')}) a tenté d'accéder à {data.get('path')} depuis {data['ip']} - NIVEAU CRITIQUE",
        )
        await broadcast_alert(alert)
        await db.commit()

    log.critical(
        f"[BANK_FRAUD_ATTEMPT] ⚠️ CRITICAL ⚠️ {data['ip']} - "
        f"User: {data.get('username')} (Role: {data.get('role')}) - Path: {data.get('path')}"
    )
```

---

### 8.3 Logger Service (`secureDataMonitor/services/logger.py`)

**Classe :** `SecurityLogger`

**Responsabilités :**
- Journalisation événements dans BDD
- Création alertes
- Écriture fichier `logs/security.log`
- Méthodes utilitaires

**Fonctions Clés :**

#### `log_event(db, event_type, severity, username, ip_address, description, action_taken)`
```python
async def log_event(
    db: AsyncSession,
    event_type: EventType,
    severity: SeverityLevel,
    username: Optional[str],
    ip_address: str,
    description: str,
    action_taken: Optional[str] = None
) -> SecurityEvent:
    """
    Crée et persiste événement sécurité
    
    Actions:
    1. Crée instance SecurityEvent
    2. Add to session
    3. Flush (pour obtenir ID)
    4. Write to security.log file
    5. Return event (avec ID généré)
    """
```

#### `create_alert(db, level, source_event_id, message)`
```python
async def create_alert(
    db: AsyncSession,
    level: SeverityLevel,
    source_event_id: UUID,
    message: str
) -> Alert:
    """
    Crée alerte liée à événement
    
    Actions:
    1. Crée instance Alert
    2. Link to source_event_id
    3. Add to session
    4. Flush
    5. Return alert
    """
```

#### `write_to_log_file(event_type, severity, message)`
```python
def write_to_log_file(event_type: str, severity: str, message: str):
    """
    Écrit dans logs/security.log
    
    Format:
    [2026-04-03 14:30:00] [CRITICAL] [BANK_FRAUD_ATTEMPT] Message...
    """
```

---

## 9. Règles de Détection

### 9.1 Detection Service (`secureDataMonitor/services/detection.py`)

**Responsabilités :**
- Implémentation 7 règles de détection
- Fonctions booléennes retournant True si règle déclenchée
- Tracking état pour règles temporelles (fenêtres glissantes)

---

### Règle 1 : Brute Force Detection

**Fonction :** `check_brute_force(username, ip, db)`  
**Seuil :** 3 échecs en < 120 secondes  
**Action :** Verrouillage automatique compte

**Logique :**
```python
async def check_brute_force(username: str, ip: str, db: AsyncSession) -> bool:
    # Query: SELECT COUNT(*) FROM login_attempts
    #        WHERE username_tried = :username
    #        AND success = FALSE
    #        AND timestamp > NOW() - INTERVAL '120 seconds'
    
    if count >= 3:
        # Lock account
        user.is_locked = True
        await db.commit()
        return True
    return False
```

---

### Règle 2 : SQL Injection Detection

**Fonction :** `check_sql_injection(input_string)`  
**Patterns détectés :**
- `' OR '1'='1`
- `UNION SELECT`
- `; DROP TABLE`
- `--` (commentaire SQL)
- `/* */` (commentaire multi-ligne)

**Logique :**
```python
def check_sql_injection(input_string: str) -> bool:
    sql_patterns = [
        r"(\b(OR|AND)\b\s+\d+=\d+)",
        r"(UNION\s+SELECT)",
        r"(;\s*DROP\s+TABLE)",
        r"(--)",
        r"(/\*.*?\*/)"
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False
```

**Intégration :** Dans exception handler 400 ou middleware

---

### Règle 3 : Unauthorized Access Detection

**Fonction :** `check_admin_access(path, role)`  
**Routes protégées :** `/soc/*`, `/admin/*`  
**Rôles autorisés :** Selon route

**Logique :**
```python
def check_admin_access(path: str, role: str) -> bool:
    if path.startswith("/soc/") and role != "soc":
        return True  # Non autorisé
    if path.startswith("/admin/") and role not in ["soc", "directeur"]:
        return True  # Non autorisé
    return False
```

---

### Règle 4 : Mass Data Access Detection

**Fonction :** `record_data_access(username, ip, db)`  
**Seuil :** >20 accès en < 60 secondes  
**Tracking :** Dictionnaire global `access_counts`

**Logique :**
```python
access_counts = {}  # {(username, ip): [(timestamp), ...]}

async def record_data_access(username: str, ip: str, db: AsyncSession) -> bool:
    key = (username, ip)
    now = time.time()
    
    # Initialize or cleanup old entries
    if key not in access_counts:
        access_counts[key] = []
    access_counts[key] = [t for t in access_counts[key] if now - t < 60]
    
    # Add current access
    access_counts[key].append(now)
    
    if len(access_counts[key]) > 20:
        # CRITICAL: Mass exfiltration detected
        return True
    return False
```

---

### Règle 5 : Enumeration Detection

**Fonction :** `check_enumeration(ip, db)`  
**Seuil :** 3 usernames différents depuis même IP en < 300 secondes  
**Tracking :** Dictionnaire `enum_attempts`

**Logique :**
```python
enum_attempts = {}  # {ip: [(username, timestamp), ...]}

async def check_enumeration(ip: str, db: AsyncSession) -> bool:
    now = time.time()
    
    if ip not in enum_attempts:
        enum_attempts[ip] = []
    
    # Cleanup old
    enum_attempts[ip] = [(u, t) for u, t in enum_attempts[ip] if now - t < 300]
    
    # Get unique usernames
    unique_usernames = set(u for u, _ in enum_attempts[ip])
    
    if len(unique_usernames) >= 3:
        return True  # Enumeration detected
    return False
```

---

### Règle 6 : Off-Hours Access Detection

**Fonction :** `check_off_hours()`  
**Plage interdite :** 20h00 - 07h00 UTC  
**Sévérité :** LOW (juste logging)

**Logique :**
```python
def check_off_hours() -> bool:
    now = datetime.utcnow()
    hour = now.hour
    
    # Off hours: 20:00 to 07:00
    if hour >= 20 or hour < 7:
        return True
    return False
```

---

### Règle 7 : Bank Fraud Attempt Detection ⭐

**Fonction :** `check_unauthorized_report_access(path, role)`  
**Routes sensibles :**
- `/direction/rapport` → directeur uniquement
- `/comptabilite/rapport` → comptable + directeur

**Sévérité :** **CRITICAL**

**Logique :**
```python
def check_unauthorized_report_access(path: str, role: str) -> bool:
    sensitive_reports = ["/direction/rapport", "/comptabilite/rapport"]
    
    is_sensitive = any(path.startswith(r) for r in sensitive_reports)
    if not is_sensitive:
        return False
    
    if path.startswith("/direction/rapport"):
        if role != "directeur":
            log.warning(f"[Règle 7] Vol dossiers: rôle='{role}' sur {path}")
            return True
    
    elif path.startswith("/comptabilite/rapport"):
        if role not in ["comptable", "directeur"]:
            log.warning(f"[Règle 7] Vol dossiers: rôle='{role}' sur {path}")
            return True
    
    return False
```

**Intégration dans main.py :**
```python
@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    
    # Règle 7
    if check_unauthorized_report_access(request.url.path, role):
        await dispatcher.emit("bank_fraud_attempt", {
            "ip": request.client.host,
            "username": username,
            "role": role,
            "path": request.url.path,
            "severity": "CRITICAL",
        })
```

---

## 10. Flux de Données

### 10.1 Flux Authentification

```
1. User submit login form
   ↓
2. POST /auth/login
   ↓
3. auth_service.authenticate_user()
   ├─ Search user by email
   ├─ Check is_locked
   ├─ Verify password (bcrypt threadpool)
   ├─ If fail: increment_failed_attempts()
   │            check_brute_force() → Rule 1
   │            emit("login_failed")
   └─ If success: reset_failed_attempts()
                emit("login_success")
   ↓
4. Create signed session cookie
   ↓
5. Redirect to role-specific dashboard
```

---

### 10.2 Flux Détection Intrusion

```
1. User action triggers detection check
   ↓
2. Detection function returns True
   ↓
3. dispatcher.emit("event_type", data)
   ↓
4. EventDispatcher notifies all subscribed handlers
   ↓
5. Handler executes:
   ├─ sec_logger.log_event() → security_events table
   ├─ sec_logger.create_alert() → alerts table (if needed)
   ├─ broadcast_event() → WebSocket (if connected)
   ├─ broadcast_alert() → WebSocket (if alert created)
   └─ Automatic actions (lock account, etc.)
   ↓
6. write_to_log_file() → logs/security.log
   ↓
7. WebSocket pushes to frontend
   ↓
8. ws_alerts.js receives and batches update
   ↓
9. requestAnimationFrame renders to DOM
```

---

### 10.3 Flux Génération Rapport PDF

```
1. Director accesses GET /direction/rapport
   ↓
2. require_role("directeur") validates
   ↓
3. Query all bank_accounts ORDER BY classification, id_compte
   ↓
4. Group accounts: {public: [], confidentiel: [], secret: []}
   ↓
5. Calculate totals per group + global
   ↓
6. Initialize FPDF()
   ↓
7. Add page, set fonts
   ↓
8. Write header (title, date, generator)
   ↓
9. Write global statistics box
   ↓
10. For each classification:
    ├─ Set fill color (green/orange/red)
    ├─ Write section header
    ├─ Write sub-total
    └─ For each account:
       ├─ Write row: ID | Titulaire | Solde | Dates
       └─ Auto page break if needed
   ↓
11. Output PDF to bytes
   ↓
12. Return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "inline; filename=..."}
    )
   ↓
13. Browser displays PDF inline
```

---

### 10.4 Flux Virement Client

```
1. Client submits transfer form
   ↓
2. POST /client/transfers
   ↓
3. Validate:
   ├─ Amount > 0
   ├─ Source account exists & belongs to user
   ├─ Destination account exists
   └─ Sufficient balance
   ↓
4. Begin database transaction
   ↓
5. Debit source account:
   ├─ source.solde -= amount
   ├─ Add debit entry to source.historique (JSON)
   ↓
6. Credit destination account:
   ├─ dest.solde += amount
   ├─ Add credit entry to dest.historique (JSON)
   ↓
7. Commit transaction
   ↓
8. If error: Rollback
   ↓
9. Redirect to dashboard with success/error message
```

---

## Annexes

### A. Commandes Utiles

**Initialisation BDD :**
```bash
psql $DATABASE_URL < init_db.sql
psql $DATABASE_URL < seed_data.sql
```

**Lancement développement :**
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Lancement production :**
```bash
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

**Voir logs temps réel :**
```bash
tail -f logs/security.log
```

---

### B. Variables d'Environnement

```env
# Base de données
DATABASE_URL=postgresql+asyncpg://user:pass@host:port/dbname

# Sécurité
SECRET_KEY=votre_cle_secrete_tres_longue

# Détection - Fenêtres temporelles
BRUTE_FORCE_WINDOW=120
MAX_LOGIN_ATTEMPTS=3
MASS_ACCESS_WINDOW=60
MASS_ACCESS_LIMIT=20
ENUM_WINDOW=300
ENUM_USERNAMES_LIMIT=3

# Détection - Horaires
ALLOWED_HOURS_START=7
ALLOWED_HOURS_END=20

# Logging
LOG_FILE_PATH=logs/security.log
```

---

### C. Codes Couleur Classification

| Classification | Couleur Hex | Usage |
|---------------|-------------|-------|
| PUBLIC | `#10b981` (vert) | Comptes accessibles comptabilité |
| CONFIDENTIEL | `#f59e0b` (orange) | Comptes sensibles |
| SECRET | `#ef4444` (rouge) | Comptes ultra-sensibles (directeur seul) |

---

### D. Sévérité Alertes

| Niveau | Couleur | Description | Temps Réponse |
|--------|---------|-------------|---------------|
| LOW | 🟢 Vert | Information normale | Pas d'action requise |
| MEDIUM | 🟡 Jaune | Attention requise | Investigation sous 1h |
| HIGH | 🟠 Orange | Danger détecté | Action immédiate |
| CRITICAL | 🔴 Rouge | Urgence absolue | **Action immédiate obligatoire** |

---

### E. Checklist Sécurité Production

- [ ] HTTPS activé
- [ ] SECRET_KEY changé (pas valeur par défaut)
- [ ] Database credentials sécurisés
- [ ] Rate limiting configuré
- [ ] Logs rotatifs activés
- [ ] Backups automatiques BDD
- [ ] Monitoring uptime configuré
- [ ] WAF/IDS en place
- [ ] Audit externe réalisé
- [ ] Plan disaster recovery testé

---

## Conclusion

Ce document couvre l'intégralité de l'architecture XUD-Bank :

✅ **Application bancaire** complète avec RBAC strict  
✅ **5 modèles de données** avec relations et index  
✅ **5 routers** segmentés par rôle métier  
✅ **Services métier** avec threadpool pour opérations bloquantes  
✅ **Templates Jinja2** avec design system cohérent  
✅ **Moteur de surveillance** événementiel temps réel  
✅ **7 règles de détection** incluant vol dossiers bancaires  
✅ **Système Pub/Sub** asynchrone performant  
✅ **WebSockets** avec batching haute performance  
✅ **Rapports PDF** structurés groupés par classification  

**Pour toute question technique, se référer aux sections correspondantes.**

---

*Document généré pour CLAUDE - Avril 2026*
