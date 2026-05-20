-- =============================================================================
-- sec_22_cert_and_key_expiry.sql
-- Priority: HIGH
-- Purpose: Surface time-to-expiry for credentials and TLS certificates.
--          Expired certificates cause hard outages; expired passwords
--          cause silent auth failures on the next login.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Server-side TLS settings + file paths
-- ---------------------------------------------------------------------------
SELECT name, setting, source
FROM pg_settings
WHERE name IN (
    'ssl',
    'ssl_cert_file',
    'ssl_key_file',
    'ssl_ca_file',
    'ssl_crl_file',
    'ssl_min_protocol_version',
    'ssl_max_protocol_version',
    'ssl_ciphers',
    'password_encryption'
)
ORDER BY name;

-- ---------------------------------------------------------------------------
-- Role expiration dates (rolvaliduntil) — password / account expiry.
-- These are *the only* cert-like expiry visible purely from SQL in PG;
-- TLS-cert expiry requires a filesystem read (openssl) outside the DB.
-- ---------------------------------------------------------------------------
SELECT
    rolname,
    rolcanlogin,
    rolvaliduntil,
    CASE
        WHEN rolvaliduntil IS NULL                       THEN 'no expiry'
        WHEN rolvaliduntil = 'infinity'::timestamptz     THEN 'no expiry (infinity)'
        WHEN rolvaliduntil < now()                       THEN 'EXPIRED'
        WHEN rolvaliduntil < now() + interval '30 days'  THEN 'expiring within 30 days'
        WHEN rolvaliduntil < now() + interval '90 days'  THEN 'expiring within 90 days'
        ELSE 'ok'
    END                                                   AS expiry_state,
    -- 'infinity' rolvaliduntil produces an infinite interval which fails to
    -- cast to int; treat infinity (and the rare -infinity) as NULL.
    CASE
        WHEN rolvaliduntil IS NULL                       THEN NULL
        WHEN rolvaliduntil =  'infinity'::timestamptz    THEN NULL
        WHEN rolvaliduntil = '-infinity'::timestamptz    THEN NULL
        ELSE EXTRACT(day FROM rolvaliduntil - now())::int
    END                                                   AS days_until_expiry
FROM pg_roles
WHERE rolcanlogin = true
ORDER BY rolvaliduntil NULLS LAST;

-- ---------------------------------------------------------------------------
-- Currently-connected sessions using SSL — confirms the cert is actually
-- in use, not just configured.
-- pg_stat_ssl column list: pid, ssl, version, cipher, bits, client_dn.
-- ---------------------------------------------------------------------------
SELECT
    COUNT(*)                                             AS total_sessions,
    COUNT(*) FILTER (WHERE s.ssl)                        AS ssl_sessions,
    COUNT(*) FILTER (WHERE NOT s.ssl)                    AS plaintext_sessions,
    COUNT(DISTINCT s.version)                            AS distinct_tls_versions,
    COUNT(DISTINCT s.cipher)                             AS distinct_ciphers
FROM pg_stat_ssl s
JOIN pg_stat_activity a ON a.pid = s.pid
WHERE a.backend_type = 'client backend';

-- Per-session TLS detail — operator spots old ciphers / protocol
SELECT
    s.pid,
    a.datname,
    a.usename,
    a.client_addr,
    s.ssl,
    s.version                                            AS tls_version,
    s.cipher,
    s.bits,
    LEFT(s.client_dn, 200)                               AS client_dn
FROM pg_stat_ssl s
JOIN pg_stat_activity a ON a.pid = s.pid
WHERE a.backend_type = 'client backend'
ORDER BY s.ssl DESC, s.version;

-- ---------------------------------------------------------------------------
-- Subscriptions and foreign-server options may carry embedded
-- certificate paths / passphrases; surface them so the operator knows
-- to check those files' filesystem dates as well.
-- pg_foreign_server.srvoptions sample: {sslmode=require, sslcert=...}
-- ---------------------------------------------------------------------------
SELECT
    s.srvname                                            AS foreign_server,
    fdw.fdwname                                          AS fdw,
    (SELECT string_agg(opt, ', ')
       FROM unnest(s.srvoptions) AS opt
      WHERE opt ~* '^(ssl|cert|key|ca)' )                AS tls_related_options
FROM pg_foreign_server s
JOIN pg_foreign_data_wrapper fdw ON fdw.oid = s.srvfdw
WHERE EXISTS (SELECT 1 FROM unnest(s.srvoptions) AS opt
               WHERE opt ~* '^(ssl|cert|key|ca)')
ORDER BY s.srvname;

-- ---------------------------------------------------------------------------
-- Summary + operator action
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM pg_roles
      WHERE rolcanlogin
        AND rolvaliduntil IS NOT NULL
        AND rolvaliduntil <> 'infinity'::timestamptz
        AND rolvaliduntil < now())                                               AS expired_logins,
    (SELECT COUNT(*) FROM pg_roles
      WHERE rolcanlogin
        AND rolvaliduntil IS NOT NULL
        AND rolvaliduntil <> 'infinity'::timestamptz
        AND rolvaliduntil BETWEEN now() AND now() + interval '30 days')          AS expiring_30d,
    (SELECT setting FROM pg_settings WHERE name = 'ssl')                         AS ssl_enabled,
    (SELECT setting FROM pg_settings WHERE name = 'ssl_cert_file')               AS ssl_cert_file,
    'Run ''openssl x509 -enddate -noout -in <ssl_cert_file>'' on the server host to read the TLS cert expiry — not visible via SQL.'
                                                                                 AS operator_action;
