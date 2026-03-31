-- ============================================================
-- XUD-BANK — SecureDataMonitor
-- Données de test (seed_data.sql) — final
-- Université de Kara – FAST-LPSIC S6 | 2025-2026
-- ============================================================
-- Identifiants :
--   soc        → Soc@1234         (admin SOC)
--   directeur  → Directeur@1234   (directeur général DG)
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
    'soc',
    'soc@xud-bank.com',
    '$2b$12$9iJQsLFaA4X7ghXMDpasW.oVoyJJo1rUsDzph3iHrg/up3D7i7LPS',
    'admin',
    FALSE, 0,
    NOW() - INTERVAL '60 days'
),
(
    'a0000000-0000-0000-0000-000000000002',
    'directeur',
    'directeur@xud-bank.com',
    '$2b$12$nd0TBQKoWTuVet8N26Q39eYr8PlubGGZvqEE0aIICgBrJKzjIskX.',
    'directeur',
    FALSE, 0,
    NOW() - INTERVAL '45 days'
),
(
    'a0000000-0000-0000-0000-000000000003',
    'hor',
    'hor@xud-bank.com',
    '$2b$12$IZeLHftJzxMTUydLcHiyZOey32tMhy7emAvC2p1t4DdRl4CfTTGaK',
    'comptable',
    FALSE, 0,
    NOW() - INTERVAL '30 days'
),
(
    'a0000000-0000-0000-0000-000000000004',
    'dupont',
    'dupont@mail.com',
    '$2b$12$8PTu.5itPRsmGsup7KZQDOyeJV23nxx.wVL4u..j2CvQMGA/e7KpG',
    'utilisateur',
    FALSE, 0,
    NOW() - INTERVAL '20 days'
),
(
    'a0000000-0000-0000-0000-000000000005',
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
    'Dupont',
    15750.00,
    '[
        {"date": "2026-03-01", "type": "virement", "montant": -500.00,  "libelle": "Loyer Mars"},
        {"date": "2026-03-05", "type": "credit",   "montant": 2500.00,  "libelle": "Salaire Mars"},
        {"date": "2026-03-10", "type": "debit",    "montant": -120.50,  "libelle": "EDF Facture"},
        {"date": "2026-03-15", "type": "debit",    "montant": -45.00,   "libelle": "Abonnement Netflix"},
        {"date": "2026-03-20", "type": "virement", "montant": -200.00,  "libelle": "Epargne"}
    ]',
    'confidentiel',
    'a0000000-0000-0000-0000-000000000004',
    NOW() - INTERVAL '30 days'
),
(
    'b0000000-0000-0000-0000-000000000002',
    'XUD-FR-002-2024',
    'Dupont',
    3200.00,
    '[
        {"date": "2026-03-20", "type": "credit", "montant": 200.00, "libelle": "Virement depuis compte principal"}
    ]',
    'public',
    'a0000000-0000-0000-0000-000000000004',
    NOW() - INTERVAL '25 days'
),

-- Compte de pierre (utilisateur/client)
(
    'b0000000-0000-0000-0000-000000000003',
    'XUD-FR-003-2024',
    'Pierre',
    4980.75,
    '[
        {"date": "2026-03-01", "type": "credit", "montant": 1800.00, "libelle": "Salaire"},
        {"date": "2026-03-03", "type": "debit",  "montant": -750.00, "libelle": "Loyer"},
        {"date": "2026-03-12", "type": "debit",  "montant": -89.99,  "libelle": "Assurance auto"},
        {"date": "2026-03-18", "type": "debit",  "montant": -35.00,  "libelle": "Abonnement mobile"}
    ]',
    'confidentiel',
    'a0000000-0000-0000-0000-000000000005',
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
    'a0000000-0000-0000-0000-000000000002',
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
    'a0000000-0000-0000-0000-000000000002',
    NOW() - INTERVAL '90 days'
),

-- Compte public (visible par tous)
(
    'a0000000-0000-0000-0000-000000000005',
    'XUD-FR-005-2024',
    'Compte Epargne Commun',
    12500.00,
    '[
        {"date": "2026-03-10", "type": "credit", "montant": 500.00, "libelle": "Versement mensuel"},
        {"date": "2026-02-10", "type": "credit", "montant": 500.00, "libelle": "Versement mensuel"},
        {"date": "2026-01-10", "type": "credit", "montant": 500.00, "libelle": "Versement mensuel"}
    ]',
    'public',
    'a0000000-0000-0000-0000-000000000002',
    NOW() - INTERVAL '60 days'
);

-- ── LOGIN ATTEMPTS ─────────────────────────────────────────────

INSERT INTO login_attempts (ip_address, username_tried, timestamp, success) VALUES
('102.89.45.12',  'dupont',    NOW() - INTERVAL '2 hours',  TRUE),
('197.234.12.88', 'pierre',    NOW() - INTERVAL '3 hours',  TRUE),
('10.0.0.5',      'soc',     NOW() - INTERVAL '4 hours',  TRUE),
('10.0.0.5',      'directeur', NOW() - INTERVAL '5 hours',  TRUE),
-- Brute force simulé
('185.220.101.5', 'pierre',     NOW() - INTERVAL '6 days',   FALSE),
('185.220.101.5', 'pierre',     NOW() - INTERVAL '6 days' + INTERVAL '30 seconds',  FALSE),
('185.220.101.5', 'pierre',     NOW() - INTERVAL '6 days' + INTERVAL '90 seconds',  FALSE),
-- Énumération simulée
('91.108.4.123',  'root',      NOW() - INTERVAL '1 hour',                          FALSE),
('91.108.4.123',  'superuser', NOW() - INTERVAL '1 hour' + INTERVAL '1 minute',    FALSE),
('91.108.4.123',  'god',       NOW() - INTERVAL '1 hour' + INTERVAL '2 minutes',   FALSE),
-- Tentatives récentes
('45.33.32.156',  'soc',     NOW() - INTERVAL '10 minutes', FALSE),
('45.33.32.156',  'soc',     NOW() - INTERVAL '8 minutes',  FALSE);


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