-- ============================================================
-- XUD-BANK — SecureDataMonitor
-- Données de test (seed_data.sql) — final
-- Université de Kara – FAST-LPSIC S6 | 2025-2026
-- ============================================================
-- Identifiants :
--   admin      → Admin@1234       (admin SOC)
--   soc        → Soc@1234         (admin SOC)
--   directeur  → Directeur@1234   (directeur général)
--   hor        → Hor@1234         (comptable)
--   dupont     → Dupont@1234      (client)
--   pierre     → Pierre@1234      (client)
-- ============================================================

-- ── Nettoyage ─────────────────────────────────────────────────
TRUNCATE alerts, security_events, login_attempts, bank_accounts, users RESTART IDENTITY CASCADE;

-- ── USERS ────────────────────────────────────────────────────

INSERT INTO users (id, username, email, password_hash, role, is_locked, failed_attempts, created_at) VALUES
(
    'a0000000-0000-0000-0000-000000000001',
    'admin',
    'admin@xud-bank.com',
    '$2b$12$HtRvU3VaU7nJ.tdhKqqC7eaDSO6pehb4Eu8aZHdokp9ZLcqZKNrbW',
    'admin',
    FALSE, 0,
    NOW() - INTERVAL '90 days'
),
(
    'a0000000-0000-0000-0000-000000000002',
    'soc',
    'soc@xud-bank.com',
    '$2b$12$9iJQsLFaA4X7ghXMDpasW.oVoyJJo1rUsDzph3iHrg/up3D7i7LPS',
    'admin',
    FALSE, 0,
    NOW() - INTERVAL '60 days'
),
(
    'a0000000-0000-0000-0000-000000000003',
    'directeur',
    'directeur@xud-bank.com',
    '$2b$12$nd0TBQKoWTuVet8N26Q39eYr8PlubGGZvqEE0aIICgBrJKzjIskX.',
    'directeur',
    FALSE, 0,
    NOW() - INTERVAL '45 days'
),
(
    'a0000000-0000-0000-0000-000000000004',
    'hor',
    'hor@xud-bank.com',
    '$2b$12$IZeLHftJzxMTUydLcHiyZOey32tMhy7emAvC2p1t4DdRl4CfTTGaK',
    'comptable',
    FALSE, 0,
    NOW() - INTERVAL '30 days'
),
(
    'a0000000-0000-0000-0000-000000000005',
    'dupont',
    'dupont@mail.com',
    '$2b$12$8PTu.5itPRsmGsup7KZQDOyeJV23nxx.wVL4u..j2CvQMGA/e7KpG',
    'utilisateur',
    FALSE, 0,
    NOW() - INTERVAL '20 days'
),
(
    'a0000000-0000-0000-0000-000000000006',
    'pierre',
    'pierre@mail.com',
    '$2b$12$/rsiWDvoI6b5Xk06kLwnb.bscs1QqvlCiXKHWs1/oAtNvMUPiO1oe',
    'utilisateur',
    FALSE, 0,
    NOW() - INTERVAL '10 days'
);

-- ── BANK ACCOUNTS ─────────────────────────────────────────────

INSERT INTO bank_accounts (id, id_compte, titulaire, solde, historique, classification, owner_id, created_at) VALUES

-- Comptes de dupont (utilisateur/client)
(
    'b0000000-0000-0000-0000-000000000001',
    'XUD-FR-001-2024',
    'Jean Dupont',
    15750.00,
    '[
        {"date": "2026-03-01", "type": "virement", "montant": -500.00,  "libelle": "Loyer Mars"},
        {"date": "2026-03-05", "type": "credit",   "montant": 2500.00,  "libelle": "Salaire Mars"},
        {"date": "2026-03-10", "type": "debit",    "montant": -120.50,  "libelle": "EDF Facture"},
        {"date": "2026-03-15", "type": "debit",    "montant": -45.00,   "libelle": "Abonnement Netflix"},
        {"date": "2026-03-20", "type": "virement", "montant": -200.00,  "libelle": "Epargne"}
    ]',
    'confidentiel',
    'a0000000-0000-0000-0000-000000000005',
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
    'a0000000-0000-0000-0000-000000000005',
    NOW() - INTERVAL '25 days'
),

-- Compte de pierre (utilisateur/client)
(
    'b0000000-0000-0000-0000-000000000003',
    'XUD-FR-003-2024',
    'Pierre Martin',
    4980.75,
    '[
        {"date": "2026-03-01", "type": "credit", "montant": 1800.00, "libelle": "Salaire"},
        {"date": "2026-03-03", "type": "debit",  "montant": -750.00, "libelle": "Loyer"},
        {"date": "2026-03-12", "type": "debit",  "montant": -89.99,  "libelle": "Assurance auto"},
        {"date": "2026-03-18", "type": "debit",  "montant": -35.00,  "libelle": "Abonnement mobile"}
    ]',
    'confidentiel',
    'a0000000-0000-0000-0000-000000000006',
    NOW() - INTERVAL '10 days'
),

-- Compte SECRET (visible directeur uniquement)
(
    'b0000000-0000-0000-0000-000000000004',
    'XUD-FR-004-2024',
    'Compte Confidentiel VIP',
    87430.50,
    '[
        {"date": "2026-02-28", "type": "credit",   "montant": 50000.00, "libelle": "Vente immobilier"},
        {"date": "2026-03-02", "type": "debit",    "montant": -1200.00, "libelle": "Charges copropriete"},
        {"date": "2026-03-08", "type": "virement", "montant": -5000.00, "libelle": "Placement SCPI"},
        {"date": "2026-03-15", "type": "credit",   "montant": 3500.00,  "libelle": "Loyers percus"}
    ]',
    'secret',
    'a0000000-0000-0000-0000-000000000003',
    NOW() - INTERVAL '20 days'
),

-- Réserve interne banque (SECRET)
(
    'b0000000-0000-0000-0000-000000000005',
    'XUD-INT-001-2024',
    'XUD-Bank Reserve Interne',
    5000000.00,
    '[
        {"date": "2026-01-01", "type": "credit", "montant": 5000000.00, "libelle": "Dotation initiale"},
        {"date": "2026-02-01", "type": "debit",  "montant": -250000.00, "libelle": "Frais operationnels Q1"},
        {"date": "2026-03-01", "type": "credit", "montant": 150000.00,  "libelle": "Remboursements clients"}
    ]',
    'secret',
    'a0000000-0000-0000-0000-000000000003',
    NOW() - INTERVAL '90 days'
),

-- Compte public (visible par tous)
(
    'b0000000-0000-0000-0000-000000000006',
    'XUD-FR-005-2024',
    'Compte Epargne Commun',
    12500.00,
    '[
        {"date": "2026-03-10", "type": "credit", "montant": 500.00, "libelle": "Versement mensuel"},
        {"date": "2026-02-10", "type": "credit", "montant": 500.00, "libelle": "Versement mensuel"},
        {"date": "2026-01-10", "type": "credit", "montant": 500.00, "libelle": "Versement mensuel"}
    ]',
    'public',
    'a0000000-0000-0000-0000-000000000004',
    NOW() - INTERVAL '60 days'
);

-- ── LOGIN ATTEMPTS ─────────────────────────────────────────────

INSERT INTO login_attempts (ip_address, username_tried, timestamp, success) VALUES
('102.89.45.12',  'dupont',    NOW() - INTERVAL '2 hours',  TRUE),
('197.234.12.88', 'pierre',    NOW() - INTERVAL '3 hours',  TRUE),
('10.0.0.5',      'admin',     NOW() - INTERVAL '4 hours',  TRUE),
('10.0.0.5',      'directeur', NOW() - INTERVAL '5 hours',  TRUE),
-- Brute force simulé
('185.220.101.5', 'admin',     NOW() - INTERVAL '6 days',   FALSE),
('185.220.101.5', 'admin',     NOW() - INTERVAL '6 days' + INTERVAL '30 seconds',  FALSE),
('185.220.101.5', 'admin',     NOW() - INTERVAL '6 days' + INTERVAL '90 seconds',  FALSE),
-- Énumération simulée
('91.108.4.123',  'root',      NOW() - INTERVAL '1 hour',                          FALSE),
('91.108.4.123',  'superuser', NOW() - INTERVAL '1 hour' + INTERVAL '1 minute',    FALSE),
('91.108.4.123',  'god',       NOW() - INTERVAL '1 hour' + INTERVAL '2 minutes',   FALSE),
-- Tentatives récentes
('45.33.32.156',  'admin',     NOW() - INTERVAL '10 minutes', FALSE),
('45.33.32.156',  'admin',     NOW() - INTERVAL '8 minutes',  FALSE);

-- ── SECURITY EVENTS ───────────────────────────────────────────

INSERT INTO security_events (timestamp, username, ip_address, event_type, severity, description, status, action_taken) VALUES

(NOW() - INTERVAL '2 hours',  'dupont',    '102.89.45.12',  'LOGIN_SUCCESS',       'LOW',
 'Connexion reussie pour dupont', 'closed', 'Aucune'),

(NOW() - INTERVAL '4 hours',  'admin',     '10.0.0.5',      'LOGIN_SUCCESS',       'LOW',
 'Connexion reussie pour admin', 'closed', 'Aucune'),

(NOW() - INTERVAL '5 hours',  'directeur', '10.0.0.5',      'LOGIN_SUCCESS',       'LOW',
 'Connexion reussie pour directeur', 'closed', 'Aucune'),

(NOW() - INTERVAL '6 days',   NULL,        '185.220.101.5', 'LOGIN_FAILED',        'MEDIUM',
 'Echec connexion #1 pour admin depuis 185.220.101.5', 'closed', 'Compteur incremente'),

(NOW() - INTERVAL '6 days' + INTERVAL '30 seconds', NULL, '185.220.101.5', 'LOGIN_FAILED', 'MEDIUM',
 'Echec connexion #2 pour admin depuis 185.220.101.5', 'closed', 'Compteur incremente'),

(NOW() - INTERVAL '6 days' + INTERVAL '90 seconds', NULL, '185.220.101.5', 'LOGIN_LOCKED', 'MEDIUM',
 'Compte admin verrouille apres 3 echecs en moins de 2 minutes', 'closed',
 'Compte verrouille (is_locked=TRUE), alerte MEDIUM creee'),

(NOW() - INTERVAL '1 hour',   NULL,        '91.108.4.123',  'UNKNOWN_USER',        'MEDIUM',
 'Tentative sur utilisateur inexistant : root', 'open', 'Tracking IP active'),

(NOW() - INTERVAL '1 hour' + INTERVAL '2 minutes', NULL, '91.108.4.123', 'ENUM_ATTEMPT', 'MEDIUM',
 'Enumeration : IP 91.108.4.123 a essaye 3 usernames differents en moins de 5 minutes', 'open',
 'Alerte MEDIUM creee, IP signalee'),

(NOW() - INTERVAL '3 hours',  NULL,        '203.0.113.42',  'SQL_INJECTION',       'HIGH',
 'Pattern SQL injection detecte dans champ login : OR 1=1 --', 'open',
 'Requete rejetee, alerte HIGH creee'),

(NOW() - INTERVAL '5 hours',  'dupont',    '102.89.45.12',  'UNAUTHORIZED_ACCESS', 'HIGH',
 'Utilisateur dupont (role=utilisateur) a tente d acces a /admin/', 'closed',
 'Redirection 403, alerte HIGH creee'),

(NOW() - INTERVAL '18 hours', 'pierre',    '197.12.45.67',  'OFF_HOURS_ACCESS',    'LOW',
 'Connexion de pierre a 02h14 UTC (hors plage 07h-20h)', 'closed',
 'Evenement logge, alerte LOW creee'),

(NOW() - INTERVAL '2 days',   NULL,        '198.51.100.77', 'SUSPICIOUS_URL',      'HIGH',
 'URL suspecte detectee : GET /admin/../../../etc/passwd', 'closed',
 'Requete bloquee, alerte HIGH creee'),

(NOW() - INTERVAL '10 minutes', NULL,      '45.33.32.156',  'LOGIN_FAILED',        'MEDIUM',
 'Echec connexion #1 pour admin depuis 45.33.32.156', 'open', 'Compteur incremente'),

(NOW() - INTERVAL '8 minutes',  NULL,      '45.33.32.156',  'LOGIN_FAILED',        'MEDIUM',
 'Echec connexion #2 pour admin depuis 45.33.32.156', 'open', 'Compteur incremente');

-- ── ALERTS ────────────────────────────────────────────────────

INSERT INTO alerts (timestamp, alert_level, source_event_id, message, resolved) VALUES
(
    NOW() - INTERVAL '6 days' + INTERVAL '90 seconds',
    'MEDIUM',
    (SELECT id FROM security_events WHERE event_type = 'LOGIN_LOCKED' LIMIT 1),
    'Compte admin verrouille : 3 echecs de connexion en moins de 2 minutes depuis 185.220.101.5',
    TRUE
),
(
    NOW() - INTERVAL '1 hour' + INTERVAL '2 minutes',
    'MEDIUM',
    (SELECT id FROM security_events WHERE event_type = 'ENUM_ATTEMPT' LIMIT 1),
    'Enumeration d identifiants : IP 91.108.4.123 a cible 3 comptes differents en 5 minutes',
    FALSE
),
(
    NOW() - INTERVAL '3 hours',
    'HIGH',
    (SELECT id FROM security_events WHERE event_type = 'SQL_INJECTION' LIMIT 1),
    'Injection SQL detectee depuis 203.0.113.42 : tentative d acces non autorise',
    FALSE
),
(
    NOW() - INTERVAL '5 hours',
    'HIGH',
    (SELECT id FROM security_events WHERE event_type = 'UNAUTHORIZED_ACCESS' LIMIT 1),
    'Acces non autorise a /admin/ par dupont (role=utilisateur)',
    TRUE
),
(
    NOW() - INTERVAL '18 hours',
    'LOW',
    (SELECT id FROM security_events WHERE event_type = 'OFF_HOURS_ACCESS' LIMIT 1),
    'Acces en dehors des heures autorisees (02h14 UTC) par pierre',
    TRUE
),
(
    NOW() - INTERVAL '2 days',
    'HIGH',
    (SELECT id FROM security_events WHERE event_type = 'SUSPICIOUS_URL' LIMIT 1),
    'Tentative de path traversal depuis 198.51.100.77 : /admin/../../../etc/passwd',
    TRUE
),
(
    NOW() - INTERVAL '8 minutes',
    'MEDIUM',
    (SELECT id FROM security_events WHERE description LIKE '%Echec connexion #2%' LIMIT 1),
    'Brute force en cours : 2 echecs pour admin depuis 45.33.32.156 — surveillance renforcee',
    FALSE
);

-- ── VERIFICATION ──────────────────────────────────────────────
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