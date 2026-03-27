-- ============================================================
-- XUD-BANK — SecureDataMonitor
-- Données de test (seed_data.sql)
-- Université de Kara – FAST-LPSIC S6 | 2025-2026
-- ============================================================
-- Mots de passe en clair (pour les tests) :
--   admin_sys    → Admin@1234
--   soc_analyst  → Analyst@1234
--   jean.dupont  → User@1234
--   marie.curie  → User@1234
--   pierre.bank  → User@1234
--   locked_user  → Lock@1234   (compte verrouillé pour démo)
-- Les hash ci-dessous sont des bcrypt cost=12
-- Régénère-les avec : python -c "from passlib.hash import bcrypt; print(bcrypt.hash('TON_MDP'))"
-- ============================================================

-- ── Nettoyage (ordre inverse des FK) ─────────────────────────
TRUNCATE alerts, security_events, login_attempts, bank_accounts, users RESTART IDENTITY CASCADE;

-- ── USERS ────────────────────────────────────────────────────

INSERT INTO users (id, username, email, password_hash, role, is_locked, failed_attempts, created_at) VALUES

-- Administrateur système
(
    'a0000000-0000-0000-0000-000000000001',
    'admin_sys',
    'admin@xud-bank.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMlJMs3OEs9SFxA3VpuWLNGrJa',  -- Admin@1234
    'admin',
    FALSE,
    0,
    NOW() - INTERVAL '90 days'
),

-- Analyste SOC
(
    'a0000000-0000-0000-0000-000000000002',
    'soc_analyst',
    'soc@xud-bank.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMlJMs3OEs9SFxA3VpuWLNGrJa',  -- Analyst@1234
    'analyste',
    FALSE,
    0,
    NOW() - INTERVAL '60 days'
),

-- Clients bancaires (utilisateur)
(
    'a0000000-0000-0000-0000-000000000003',
    'jean.dupont',
    'jean.dupont@mail.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMlJMs3OEs9SFxA3VpuWLNGrJa',  -- User@1234
    'utilisateur',
    FALSE,
    0,
    NOW() - INTERVAL '30 days'
),
(
    'a0000000-0000-0000-0000-000000000004',
    'marie.curie',
    'marie.curie@mail.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMlJMs3OEs9SFxA3VpuWLNGrJa',  -- User@1234
    'utilisateur',
    FALSE,
    0,
    NOW() - INTERVAL '20 days'
),
(
    'a0000000-0000-0000-0000-000000000005',
    'pierre.bank',
    'pierre.bank@mail.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMlJMs3OEs9SFxA3VpuWLNGrJa',  -- User@1234
    'utilisateur',
    FALSE,
    0,
    NOW() - INTERVAL '10 days'
),

-- Compte verrouillé (démo brute force)
(
    'a0000000-0000-0000-0000-000000000006',
    'locked_user',
    'locked@xud-bank.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMlJMs3OEs9SFxA3VpuWLNGrJa',  -- Lock@1234
    'utilisateur',
    TRUE,   -- déjà verrouillé
    3,
    NOW() - INTERVAL '5 days'
);

-- ── BANK ACCOUNTS (données sensibles) ─────────────────────────

INSERT INTO bank_accounts (id, id_compte, titulaire, solde, historique, classification, owner_id, created_at) VALUES

-- Comptes de jean.dupont
(
    'b0000000-0000-0000-0000-000000000001',
    'XUD-FR-001-2024',
    'Jean Dupont',
    15750.00,
    '[
        {"date": "2026-03-01", "type": "virement", "montant": -500.00, "libelle": "Loyer Mars"},
        {"date": "2026-03-05", "type": "credit",   "montant": 2500.00, "libelle": "Salaire Mars"},
        {"date": "2026-03-10", "type": "debit",    "montant": -120.50, "libelle": "EDF Facture"},
        {"date": "2026-03-15", "type": "debit",    "montant": -45.00,  "libelle": "Abonnement Netflix"},
        {"date": "2026-03-20", "type": "virement", "montant": -200.00, "libelle": "Epargne"}
    ]',
    'confidentiel',
    'a0000000-0000-0000-0000-000000000003',
    NOW() - INTERVAL '30 days'
),
(
    'b0000000-0000-0000-0000-000000000002',
    'XUD-FR-002-2024',
    'Jean Dupont',
    3200.00,
    '[
        {"date": "2026-03-20", "type": "credit", "montant": 200.00, "libelle": "Virement depuis compte principal"}
    ]',
    'public',
    'a0000000-0000-0000-0000-000000000003',
    NOW() - INTERVAL '25 days'
),

-- Comptes de marie.curie
(
    'b0000000-0000-0000-0000-000000000003',
    'XUD-FR-003-2024',
    'Marie Curie',
    87430.50,
    '[
        {"date": "2026-02-28", "type": "credit",   "montant": 50000.00, "libelle": "Vente immobilier"},
        {"date": "2026-03-02", "type": "debit",    "montant": -1200.00, "libelle": "Charges copropriete"},
        {"date": "2026-03-08", "type": "virement", "montant": -5000.00, "libelle": "Placement SCPI"},
        {"date": "2026-03-15", "type": "credit",   "montant": 3500.00,  "libelle": "Loyers percus"}
    ]',
    'secret',
    'a0000000-0000-0000-0000-000000000004',
    NOW() - INTERVAL '20 days'
),

-- Comptes de pierre.bank
(
    'b0000000-0000-0000-0000-000000000004',
    'XUD-FR-004-2024',
    'Pierre Bancroft',
    4980.75,
    '[
        {"date": "2026-03-01", "type": "credit", "montant": 1800.00, "libelle": "Salaire"},
        {"date": "2026-03-03", "type": "debit",  "montant": -750.00, "libelle": "Loyer"},
        {"date": "2026-03-12", "type": "debit",  "montant": -89.99,  "libelle": "Assurance auto"}
    ]',
    'confidentiel',
    'a0000000-0000-0000-0000-000000000005',
    NOW() - INTERVAL '10 days'
),

-- Compte interne banque (géré par analyste)
(
    'b0000000-0000-0000-0000-000000000005',
    'XUD-INT-001-2024',
    'XUD-Bank Réserve Interne',
    5000000.00,
    '[
        {"date": "2026-01-01", "type": "credit", "montant": 5000000.00, "libelle": "Dotation initiale"}
    ]',
    'secret',
    'a0000000-0000-0000-0000-000000000002',
    NOW() - INTERVAL '90 days'
);

-- ── LOGIN ATTEMPTS (historique de tentatives pour démo) ────────

INSERT INTO login_attempts (ip_address, username_tried, timestamp, success) VALUES

-- Connexions normales
('102.89.45.12',  'jean.dupont',  NOW() - INTERVAL '2 hours',   TRUE),
('102.89.45.12',  'jean.dupont',  NOW() - INTERVAL '1 day',     TRUE),
('197.234.12.88', 'marie.curie',  NOW() - INTERVAL '3 hours',   TRUE),
('10.0.0.5',      'admin_sys',    NOW() - INTERVAL '4 hours',   TRUE),

-- Brute force sur locked_user (Règle 1 — déjà déclenché)
('185.220.101.5', 'locked_user',  NOW() - INTERVAL '6 days',   FALSE),
('185.220.101.5', 'locked_user',  NOW() - INTERVAL '6 days' + INTERVAL '30 seconds', FALSE),
('185.220.101.5', 'locked_user',  NOW() - INTERVAL '6 days' + INTERVAL '90 seconds', FALSE),

-- Énumération d'identifiants depuis une IP suspecte (Règle 5)
('91.108.4.123',  'admin',        NOW() - INTERVAL '1 hour',   FALSE),
('91.108.4.123',  'root',         NOW() - INTERVAL '1 hour' + INTERVAL '1 minute',  FALSE),
('91.108.4.123',  'superuser',    NOW() - INTERVAL '1 hour' + INTERVAL '2 minutes', FALSE),

-- Tentatives récentes en cours
('45.33.32.156',  'admin_sys',    NOW() - INTERVAL '10 minutes', FALSE),
('45.33.32.156',  'admin_sys',    NOW() - INTERVAL '8 minutes',  FALSE);

-- ── SECURITY EVENTS (historique pour le dashboard) ────────────

INSERT INTO security_events (timestamp, username, ip_address, event_type, severity, description, status, action_taken) VALUES

-- Login réussis
(NOW() - INTERVAL '2 hours',  'jean.dupont', '102.89.45.12',  'LOGIN_SUCCESS', 'LOW',
 'Connexion réussie pour jean.dupont', 'closed', 'Aucune'),

(NOW() - INTERVAL '4 hours',  'admin_sys',   '10.0.0.5',      'LOGIN_SUCCESS', 'LOW',
 'Connexion réussie pour admin_sys', 'closed', 'Aucune'),

-- Brute force → verrouillage (Règle 1)
(NOW() - INTERVAL '6 days',   NULL,          '185.220.101.5', 'LOGIN_FAILED',  'MEDIUM',
 'Échec connexion #1 pour locked_user depuis 185.220.101.5', 'closed', 'Compteur incrémenté'),

(NOW() - INTERVAL '6 days' + INTERVAL '30 seconds', NULL, '185.220.101.5', 'LOGIN_FAILED', 'MEDIUM',
 'Échec connexion #2 pour locked_user depuis 185.220.101.5', 'closed', 'Compteur incrémenté'),

(NOW() - INTERVAL '6 days' + INTERVAL '90 seconds', NULL, '185.220.101.5', 'LOGIN_LOCKED', 'MEDIUM',
 'Compte locked_user verrouillé après 3 échecs en moins de 2 minutes', 'closed',
 'Compte verrouillé (is_locked=TRUE), alerte MEDIUM créée'),

-- Énumération (Règle 5)
(NOW() - INTERVAL '1 hour',   NULL,          '91.108.4.123',  'UNKNOWN_USER',  'MEDIUM',
 'Tentative sur utilisateur inexistant : admin', 'open', 'Tracking IP activé'),

(NOW() - INTERVAL '1 hour' + INTERVAL '2 minutes', NULL, '91.108.4.123', 'ENUM_ATTEMPT', 'MEDIUM',
 'Énumération détectée : IP 91.108.4.123 a essayé 3 usernames différents en moins de 5 minutes', 'open',
 'Alerte MEDIUM créée, IP signalée'),

-- Injection SQL (Règle 2)
(NOW() - INTERVAL '3 hours',  NULL,          '203.0.113.42',  'SQL_INJECTION', 'HIGH',
 'Pattern SQL injection détecté dans champ login : '' OR 1=1 --', 'open',
 'Requête rejetée, alerte HIGH créée'),

-- Accès admin non autorisé (Règle 3)
(NOW() - INTERVAL '5 hours',  'jean.dupont', '102.89.45.12',  'UNAUTHORIZED_ACCESS', 'HIGH',
 'Utilisateur jean.dupont (role=utilisateur) a tenté d''accéder à /admin/', 'closed',
 'Redirection 403, alerte HIGH créée'),

-- Accès hors horaires
(NOW() - INTERVAL '18 hours', 'pierre.bank', '197.12.45.67',  'OFF_HOURS_ACCESS', 'LOW',
 'Connexion de pierre.bank à 02h14 UTC (hors plage 07h-20h)', 'closed',
 'Événement loggé, alerte LOW créée'),

-- URL suspecte
(NOW() - INTERVAL '2 days',   NULL,          '198.51.100.77', 'SUSPICIOUS_URL', 'HIGH',
 'URL suspecte détectée : GET /admin/../../../etc/passwd', 'closed',
 'Requête bloquée, alerte HIGH créée'),

-- Tentatives récentes (actives)
(NOW() - INTERVAL '10 minutes', NULL,        '45.33.32.156',  'LOGIN_FAILED',  'MEDIUM',
 'Échec connexion #1 pour admin_sys depuis 45.33.32.156', 'open', 'Compteur incrémenté'),

(NOW() - INTERVAL '8 minutes',  NULL,        '45.33.32.156',  'LOGIN_FAILED',  'MEDIUM',
 'Échec connexion #2 pour admin_sys depuis 45.33.32.156', 'open', 'Compteur incrémenté');

-- ── ALERTS (alertes générées par les handlers) ────────────────

INSERT INTO alerts (timestamp, alert_level, source_event_id, message, resolved) VALUES

-- Alerte brute force (résolue)
(
    NOW() - INTERVAL '6 days' + INTERVAL '90 seconds',
    'MEDIUM',
    (SELECT id FROM security_events WHERE event_type = 'LOGIN_LOCKED' LIMIT 1),
    'Compte locked_user verrouillé : 3 échecs de connexion en moins de 2 minutes depuis 185.220.101.5',
    TRUE
),

-- Alerte énumération (ouverte)
(
    NOW() - INTERVAL '1 hour' + INTERVAL '2 minutes',
    'MEDIUM',
    (SELECT id FROM security_events WHERE event_type = 'ENUM_ATTEMPT' LIMIT 1),
    'Tentative d''énumération d''identifiants : IP 91.108.4.123 a ciblé 3 comptes différents en 5 minutes',
    FALSE
),

-- Alerte injection SQL (ouverte)
(
    NOW() - INTERVAL '3 hours',
    'HIGH',
    (SELECT id FROM security_events WHERE event_type = 'SQL_INJECTION' LIMIT 1),
    'Injection SQL détectée depuis 203.0.113.42 : tentative d''accès non autorisé à la base de données',
    FALSE
),

-- Alerte accès admin refusé (résolue)
(
    NOW() - INTERVAL '5 hours',
    'HIGH',
    (SELECT id FROM security_events WHERE event_type = 'UNAUTHORIZED_ACCESS' LIMIT 1),
    'Accès non autorisé à /admin/ par jean.dupont (rôle=utilisateur)',
    TRUE
),

-- Alerte hors horaires (résolue)
(
    NOW() - INTERVAL '18 hours',
    'LOW',
    (SELECT id FROM security_events WHERE event_type = 'OFF_HOURS_ACCESS' LIMIT 1),
    'Accès en dehors des heures autorisées (02h14 UTC) par pierre.bank',
    TRUE
),

-- Alerte URL suspecte (résolue)
(
    NOW() - INTERVAL '2 days',
    'HIGH',
    (SELECT id FROM security_events WHERE event_type = 'SUSPICIOUS_URL' LIMIT 1),
    'Tentative de path traversal détectée depuis 198.51.100.77 : /admin/../../../etc/passwd',
    TRUE
),

-- Alertes actives récentes (brute force en cours sur admin_sys)
(
    NOW() - INTERVAL '8 minutes',
    'MEDIUM',
    (SELECT id FROM security_events WHERE description LIKE '%Échec connexion #2%' LIMIT 1),
    'Brute force en cours : 2 échecs pour admin_sys depuis 45.33.32.156 — surveillance renforcée',
    FALSE
);

-- ============================================================
-- VÉRIFICATION
-- ============================================================
SELECT 'users'           AS table_name, COUNT(*) AS nb FROM users
UNION ALL
SELECT 'bank_accounts',                 COUNT(*)        FROM bank_accounts
UNION ALL
SELECT 'login_attempts',                COUNT(*)        FROM login_attempts
UNION ALL
SELECT 'security_events',               COUNT(*)        FROM security_events
UNION ALL
SELECT 'alerts',                        COUNT(*)        FROM alerts;

-- ============================================================
-- FIN DU SCRIPT
-- ============================================================