-- ============================================================
-- XUD-BANK — SecureDataMonitor
-- Script d'initialisation de la base de données PostgreSQL
-- Université de Kara – FAST-LPSIC S6 | 2025-2026
-- ============================================================

-- ── Extensions ───────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_uuid()

-- ── ENUMs ────────────────────────────────────────────────────

CREATE TYPE user_role AS ENUM ('admin', 'directeur', 'comptable', 'utilisateur');

CREATE TYPE account_classification AS ENUM ('public', 'confidentiel', 'secret');

CREATE TYPE event_type AS ENUM (
    'LOGIN_SUCCESS',
    'LOGIN_FAILED',
    'LOGIN_LOCKED',
    'UNKNOWN_USER',
    'UNAUTHORIZED_ACCESS',
    'PRIVILEGE_ESCALATION',
    'SQL_INJECTION',
    'RATE_LIMIT',
    'MASS_DATA_ACCESS',
    'ENUM_ATTEMPT',
    'OFF_HOURS_ACCESS',
    'SUSPICIOUS_URL'
);

CREATE TYPE severity_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

CREATE TYPE event_status AS ENUM ('open', 'investigating', 'closed');

-- ── TABLE : users ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(50) UNIQUE NOT NULL,
    email           VARCHAR(100) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            user_role   NOT NULL DEFAULT 'utilisateur',
    is_locked       BOOLEAN     NOT NULL DEFAULT FALSE,
    failed_attempts INTEGER     NOT NULL DEFAULT 0,
    last_failed_at  TIMESTAMP   NULL,
    created_at      TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── TABLE : bank_accounts (données sensibles) ─────────────────
CREATE TABLE IF NOT EXISTS bank_accounts (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    id_compte       VARCHAR(20)     UNIQUE NOT NULL,
    titulaire       VARCHAR(100)    NOT NULL,
    solde           DECIMAL(15, 2)  NOT NULL DEFAULT 0.00,
    historique      TEXT            NULL,       -- JSON sérialisé des transactions
    classification  account_classification NOT NULL DEFAULT 'confidentiel',
    owner_id        UUID            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMP       NOT NULL DEFAULT NOW()
);

-- ── TABLE : login_attempts (tracking brute force & énumération) ──
CREATE TABLE IF NOT EXISTS login_attempts (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address      INET        NOT NULL,
    username_tried  VARCHAR(50) NOT NULL,
    timestamp       TIMESTAMP   NOT NULL DEFAULT NOW(),
    success         BOOLEAN     NOT NULL
);

-- ── TABLE : security_events (journal central) ─────────────────
CREATE TABLE IF NOT EXISTS security_events (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMP       NOT NULL DEFAULT NOW(),
    username        VARCHAR(50)     NULL,           -- NULL si utilisateur inconnu
    ip_address      INET            NOT NULL,
    event_type      event_type      NOT NULL,
    severity        severity_level  NOT NULL,
    description     TEXT            NOT NULL,
    status          event_status    NOT NULL DEFAULT 'open',
    action_taken    TEXT            NULL
);

-- ── TABLE : alerts ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMP       NOT NULL DEFAULT NOW(),
    alert_level     severity_level  NOT NULL,
    source_event_id UUID            NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
    message         TEXT            NOT NULL,
    resolved        BOOLEAN         NOT NULL DEFAULT FALSE
);

-- ── INDEX (performance des requêtes fréquentes) ───────────────

-- Recherche rapide des échecs par username (Règle 1)
CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
    ON login_attempts (username_tried, timestamp DESC);

-- Recherche rapide des tentatives par IP (Règle 5)
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts (ip_address, timestamp DESC);

-- Filtres dashboard : events par type, severity, timestamp
CREATE INDEX IF NOT EXISTS idx_security_events_type
    ON security_events (event_type, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_severity
    ON security_events (severity, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_ip
    ON security_events (ip_address, timestamp DESC);

-- Alertes non résolues (dashboard)
CREATE INDEX IF NOT EXISTS idx_alerts_unresolved
    ON alerts (resolved, timestamp DESC);

-- Accès comptes par owner (Règle 4 : comptage consultations/min)
CREATE INDEX IF NOT EXISTS idx_bank_accounts_owner
    ON bank_accounts (owner_id);

-- ============================================================
-- INDEXES ADDITIONNELS POUR PERFORMANCE
-- ============================================================

-- LoginAttempt: brute force detection queries
CREATE INDEX IF NOT EXISTS idx_login_attempts_username_success_time
    ON login_attempts (username_tried, success, timestamp);

-- SecurityEvent: dashboard filtering and time-range queries
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
    ON security_events (timestamp);

CREATE INDEX IF NOT EXISTS idx_security_events_type_timestamp
    ON security_events (event_type, timestamp);

CREATE INDEX IF NOT EXISTS idx_security_events_severity_timestamp
    ON security_events (severity, timestamp);

-- Alert: unresolved alerts queries
CREATE INDEX IF NOT EXISTS idx_alerts_resolved_timestamp
    ON alerts (resolved, timestamp);

-- User: login lookup and locked user counts
CREATE INDEX IF NOT EXISTS idx_users_email
    ON users (email);

CREATE INDEX IF NOT EXISTS idx_users_is_locked
    ON users (is_locked);

-- ============================================================
-- FIN DU SCRIPT
-- ============================================================