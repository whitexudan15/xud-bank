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
7. [Moteur Événementiel](#-7-moteur-événementiel)
8. [Règles de Détection SOC](#-8-règles-de-détection-soc)
9. [Installation & Déploiement](#-9-installation--déploiement)
10. [Journalisation](#-10-journalisation)
11. [Tests des Triggers d'Événements](#-11-tests-des-triggers-dévénements)

---

## 🔍 1. Présentation

**XUD-Bank** est une application Web bancaire de démonstration destinée au personnel interne et aux clients. Elle intègre directement un moteur de détection d'intrusion appelé **SecureDataMonitor**. 

Depuis la dernière refonte architecturale, le projet applique une **Séparation des Tâches (Segregation of Duties)** stricte : l'administration monolithique a été remplacée par des espaces dédiés pour chaque métier (Sécurité, Direction, Comptabilité, Client).

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

---

## 🛠️ 3. Stack Technologique

| Composant | Technologie | Détails |
|---|---|---|
| **Backend** | FastAPI (Python 3.11+) | Asynchrone natif, routers segmentés |
| **Base de données** | PostgreSQL (Railway) | Driver haute performance `asyncpg` |
| **ORM** | SQLAlchemy 2.0 | Opérations totalement asynchrones |
| **Mots de passe** | Passlib (Bcrypt = 12) | Exécuté sur *Threadpool* (non-bloquant) |
| **Sessions** | itsdangerous | Cookies chiffrés et signés sans BDD |
| **WebSocket** | WebSockets natifs | Optimisation visuelle par Batching (`requestAnimationFrame`) |
| **Frontend** | HTML5 / Vanilla CSS / JS | Interfaces dynamiques / Chart.js / Google Fonts (Syne, Figtree) |

---

## 📁 4. Structure du Projet

```
xud-bank/
├── app/                              # Application Bancaire (Core)
│   ├── main.py                       # Point d'entrée, montage des routers & middlewares
│   ├── database.py                   # Configuration Railway + Asyncpg
│   ├── models/                       # Schémas SQLAlchemy (User, BankAccount, Alert...)
│   ├── routers/                      # Logique Role-Based Access Control
│   │   ├── auth.py                   # Auth, Sessions, Logout
│   │   ├── soc.py                    # (/soc) Surveillance & Verrouillage comptes
│   │   ├── direction.py              # (/direction) Gestion personnel (Hire/Fire)
│   │   ├── comptabilite.py           # (/comptabilite) Gestion bancaire & création comptes
│   │   └── client.py                 # (/client) Espace personnel client (Virements)
│   ├── services/                     # Métier (auth via threadpool)
│   └── templates/                    # Front segmenté par rôle (soc/, direction/, etc.)
├── secureDataMonitor/                # SOC Engine (Composant de Surveillance)
│   ├── events/                       # Handlers & Dispatcher d'événements
│   ├── services/                     # Détection de menaces / Logger système
│   ├── routers/                      # REST API Stats & WebSockets
│   └── static/js/ws_alerts.js        # Script de batching haute performance
├── logs/                             # Fichiers de log locaux (security.log)
└── init_db.sql / seed_data.sql       # Initialisation & Données de démo
```

---

## 💾 5. Modèle de Données

Le modèle repose sur PostgreSQL :

- **`users`** : UUID, identifiants, roles (`soc`, `directeur`, `comptable`, `utilisateur`), status de verrouillage.
- **`bank_accounts`** : Comptes bancaires avec classification (`public`, `confidentiel`, `secret`).
- **`security_events`** : Journal indélébile des incidents de sécurité détectés.
- **`alerts`** : Notifications levées par le moteur pour les administrateurs SOC.
- **`login_attempts`** : Tracking des tentatives pour la prévention brute-force.

---

## 👥 6. Identification et Rôles (RBAC)

L'inscription publique est **désactivée**. Les comptes sont créés exclusivement par la **Direction**.

| Username | Role | Espace Dédié | Privilèges & Responsabilités |
|---|---|---|---|
| **`soc`** | `soc` | `/soc/*` | Surveillance temps réel, **Verrouillage des comptes**, Logs bruts. |
| **`directeur`** | `directeur` | `/direction/*` | **Recrutement personnel**, Radiation (suppression), Audit global. |
| **`hor`** | `comptable` | `/comptabilite/*` | **Création de comptes bancaires**, Gestion des virements. |
| **`dupont`** | `utilisateur` | `/client/*` | Consultation soldes, **Virements personnels**, Historique. |

---

## ⚡ 7. Moteur Événementiel

Le système utilise `Dispatcher` asynchrone pour traiter les menaces sans ralentir l'utilisateur :

```python
# Exemple de levée d'incident
await dispatcher.emit("mass_data_access", {
    "ip": "102.85.x.x",
    "username": "suspect_user",
    "count": 45
})
```

---

## 🚨 8. Règles de Détection SOC

Le moteur Monitor écoute et réagit selon les politiques suivantes :

| Règle | Description | Déclencheur | Réaction | Alerte |
|---|---|---|---|---|
| **Règle 1** | Brute Force | 3 échecs en < 2min | Verrouillage automatique du compte | **MEDIUM** |
| **Règle 2** | Injection SQL | Patterns `' OR 1=1`, `--`, etc | Rejet 400 immédiat + Log Payload | **HIGH** |
| **Règle 3** | Accès Illégitime | Client tentant `/soc/*` ou `/direction/*` | Permission Denied (403) | **HIGH** |
| **Règle 4** | Exfiltration | >20 accès aux données en 1min | Signalement suspicion exfiltration | **CRITICAL** |
| **Règle 5** | Énumération | 3 usernames différents depuis une IP | Fichage et surveillance de l'IP | **MEDIUM** |
| **Règle 6** | Off-Hours | Connexion entre 20h00 et 07h00 | Inscription discrète de l'événement | **LOW** |

---

## 🚀 9. Installation & Déploiement

### Initialisation

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer l'environnement (.env)
# DATABASE_URL=postgresql+asyncpg://user:pass@host:port/db
# SECRET_KEY=cle_secrete_longue

# 3. Initialiser la structure et les rôles (Remise à zéro complète)
psql $DATABASE_URL < init_db.sql
psql $DATABASE_URL < seed_data.sql

# 4. Lancer le serveur
uvicorn app.main:app --reload
```

---

## 📝 10. Journalisation

La sécurité s'accompagne d'une visibilité totale :
1. **Fichiers Locaux** : `logs/security.log` pour les analyses judiciaires.
2. **Dashboard Temps Réel** : `/soc/dashboard` via WebSockets (Regroupement `requestAnimationFrame`).
3. **Persistance Gérée** : Historique indélébile dans `security_events`.

---

## 🧪 11. Tests des Triggers d'Événements

### Test : Escalade de Privilège (Règle 3)
**Objectif** : Vérifier que les rôles sont étanches.
```bash
# Se connecter en tant que client (dupont)
curl -X POST http://localhost:8000/auth/login -d "email=dupont@mail.com&password=Dupont@1234" -c cookies.txt

# Tenter d'accéder à la console de verrouillage SOC
curl http://localhost:8000/soc/users -b cookies.txt
```
**Résultat attendu** : 403 Forbidden + Alerte HIGH dans `/soc/dashboard`.

### Test : Verrouillage SOC (Règle 1)
**Objectif** : Simuler une attaque brute-force.
```bash
for i in {1..4}; do
  curl -X POST http://localhost:8000/auth/login -d "email=directeur@xud-bank.com&password=FauxPassword"
done
```
**Résultat attendu** : Compte directeur devient `is_locked = TRUE` après 3 essais. Le SOC peut alors le déverrouiller sur `/soc/users`.

---

> *Projet réalisé par l'équipe FAST-LPSIC M2 durant la session 2025-2026. L'architecture respecte les standards de défense en profondeur (RBAC segmenté, Dispatcher asynchrone, Heartbeat WebSocket).*