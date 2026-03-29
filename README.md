# XUD-Bank — SecureDataMonitor

> Application Web bancaire sécurisée avec moteur de surveillance événementielle en temps réel.  
> Université de Kara – FAST-LPSIC S6 | Programmation Événementielle & Cybersécurité | 2025-2026

---

## 📌 Table des matières

1. [Présentation](#1-présentation)
2. [Architecture](#2-architecture)
3. [Stack technologique & Optimisations](#3-stack-technologique--optimisations)
4. [Structure du projet](#4-structure-du-projet)
5. [Modèle de données](#5-modèle-de-données)
6. [Identification et Rôles (NOUVEAU)](#6-identification-et-rôles-nouveau)
7. [Logique événementielle](#7-logique-événementielle)
8. [Règles de détection SOC](#8-règles-de-détection-soc)
9. [Installation & Déploiement](#9-installation--déploiement)
10. [Journalisation](#10-journalisation)

---

## 1. Présentation

**XUD-Bank** est une application Web bancaire de démonstration destinée au personnel interne et aux clients. Elle intègre directement un moteur de détection d'intrusion appelé **SecureDataMonitor**. Ce composant agit comme un mini-SOC (Security Operations Center) qui surveille, détecte, et alerte en temps réel toute activité suspecte sur le backend.

### Objectifs atteints
- **UI Premium** : Interface asynchrone moderne (Bootstrap 5, Jinja2, Chart.js) avec des Layouts optimisés pour les tableaux de bord interactifs.
- **Authentification asynchrone** : Hachage Bcrypt optimisé fonctionnant hors du thread principal pour éviter tout ralentissement réseau. 
- **Moteur événementiel (Pub/Sub)** : Modèle 100% découplé.
- **Détection des menaces** : 6 règles de détection (Brute force, exfiltration, SQLi...).
- **Surveillance Ultra-fluide (WebSocket)** : Tableau de bord qui supporte des centaines d'événements par seconde sans faire lagger le navigateur grâce au regroupement d'événements (`requestAnimationFrame`).

---

## 2. Architecture

Le projet suit deux design patterns combinés :

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

## 3. Stack technologique & Optimisations

| Composant | Technologie | Note |
|---|---|---|
| **Backend** | FastAPI (Python 3.11+) | Asynchrone natif |
| **Bases de données** | PostgreSQL (Railway) | Driver hautes performances `asyncpg` |
| **ORM** | SQLAlchemy 2.0 | Opérations totalement asynchrones |
| **Mots de passe** | Passlib (Bcrypt = 12) | Exécuté sur un *Threadpool* (non-bloquant) |
| **Sessions** | itsdangerous | Cookies chiffrés et signés sans BDD |
| **WebSocket** | Websockets natif | Optimisation visuelle par Batching (`requestAnimationFrame`) |
| **Frontend** | HTML5 / Bootstrap 5 / JS | Interfaces dynamiques / Chart.js mis à jour en masse |
| **Logs** | logging.RotatingFileHandler | Fichiers rotatifs & BDD locale sync |

---

## 4. Structure du projet

```
xud-bank/
├── app/                              # Application Bancaire
│   ├── main.py                       # Point d'entrée, middlewares de sécurité
│   ├── database.py                   # Configuration Railway + Asyncpg
│   ├── models/                       # UUIDPK, Enum (utilisateurs, alertes, etc)
│   ├── routers/                      # Routes d'accès
│   ├── services/                     # Métier (auth via threadpool)
│   └── templates/                    # Front public
├── secureDataMonitor/                # Surveillant / SOC Moteur
│   ├── events/                       # Handles & Dispatcher
│   ├── services/                     # Détection de menaces / Exfiltration
│   ├── routers/                      # Rest API Admin & WebSockets
│   ├── templates/admin/              # Front SOC
│   └── static/js/ws_alerts.js        # Script de batching très haute perfo
├── logs/                             # Fichiers de log locaux
└── init_db.sql / requirements.txt    # Configurations DB
```

---

## 5. Modèle de données

Le modèle repose sur PostgreSQL (avec Railway) :

- **`users`** : UUID, identifiants, mot de passe hashé, rôles et gestion de verrouillage (`is_locked`).
- **`bank_accounts`** : Données cibles (soldes, niveau de classification "secret" etc.).
- **`security_events`** : Trace indélébile en base des actions (avec typage Enum). 
- **`alerts`** : Alertes levées par le SOC, liées aux `security_events` déclencheurs.
- **`login_attempts`** : Historique granulaire pour la prévention du brute-force Règle 1 et de l'énumération Règle 5.

*(Voir l'intégrité de schéma au fichier `init_db.sql`)*

---

## 6. Identification et Rôles (NOUVEAU)

Voici les identifiants mis à jour dans le système. La navigation et les accès sont fortement restreints selon le rôle validé durant la phase de connexion.

| Username | Mot de passe | Rôle | Accès & Privilèges |
|---|---|---|---|
| **`admin`** | `Admin@1234` | **admin (SOC)** | Accès complet, Dashboard Temps réel |
| **`soc`** | `Soc@1234` | **admin (SOC)** | Tableau de gestion des Alertes |
| **`hor`** | `Hor@1234` | **comptable** | Accès aux bilans |
| **`directeur`** | `Directeur@1234` | **directeur** | Accès directoire |
| **`dupont`** | `Dupont@1234` | **utilisateur (client)**| Consultation comptes personnels |
| **`pierre`** | `Pierre@1234` | **utilisateur (client)**| Consultation comptes personnels |

---

## 7. Logique événementielle

Le cœur de XUD-Bank repose sur des événements publiés par les requêtes (ex: *tentative de connexion ratée*) et attrapés en arrière plan :

```python
await dispatcher.emit("rate_limit", {
    "ip": "192.168.1.1",
    "username": "dupont",
    "count": 50
})
```

- Pas de blocage du Thread Serveur. L'utilisateur reçoit sa réponse instantanément, pendant que les modules d'analyse se lancent en parallèle.

---

## 8. Règles de détection SOC

Le module Monitor écoute activement les évènements pour bloquer le trafic :

| Règle | Description | Réaction du système | Alerte levée |
|---|---|---|---|
| **Règle 1 : Brute Force** | 3 échecs sur un seul compte en < 2min | Verrouillage du compte bloqué (`is_locked`) | **MEDIUM** |
| **Règle 2 : Injection SQL** | Strings suspectes: `' OR 1=1` | Rejet 400 immédiat + alerte | **HIGH** |
| **Règle 3 : Escalade** | Requête `/admin/*` effectuée par un *client* | Révocation avec 403 immédiat | **HIGH** |
| **Règle 4 : Exfiltration** | L'utilisateur fait +20 requêtes de data en 1m | Flag de suspicion Massive | **CRITICAL** |
| **Règle 5 : Énumération** | Une seule IP essaie différents pseudos | Fichage de l'IP | **MEDIUM** |
| **Règle 6 : Horaires** | Connexion entre 20h00 et 07h00 | Inscription silencieuse dans les registres | **LOW** |

---

## 9. Installation & Déploiement

### Prérequis
- Python 3.11+
- Base de données PostgreSQL fraîche (idéalement hébergée via Railway)

```bash
# 1. Cloner l'archive
git clone https://github.com/votre-repo/xud-bank.git
cd xud-bank

# 2. Préparer l'environnement
python -m venv venv
source venv/bin/activate

# 3. Installer les dépendances 
pip install -r requirements.txt

# 4. Variables d'environnement
cp .env.example .env
# Renseigner la clef `DATABASE_URL` (modèle asyncpg!) et `SECRET_KEY`

# 5. Lancer l'application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
Le projet se trouve désormais sur `http://localhost:8000`.

---

## 10. Journalisation

La sécurité s'accompagne toujours d'un bon logging.
1. **Fichiers Locaux** (`logs/security.log`) : Fichiers rotatifs limités à 5MB avec rotation de 3 backups. Évite la saturation du disque.
2. **Dashboard Temps Réel Websocket** : Affichage graphique des détections sans réactualisation (flux réseau optimisé).
3. **Persistance en base de donnée** : Table `security_events` et `alerts`.

---
> *Architecture réalisée par le département FAST-LPSIC M2 durant la session 2025-2026. L'outil reflète les standards défensifs Asynchrones modernes (Event-Loops, Threadpool GPU offloading, API sécurisée).*