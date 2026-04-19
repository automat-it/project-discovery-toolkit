-- =============================================================================
-- sec_22_cert_and_key_expiry.sql
-- Priority: HIGH
-- Purpose: Surface expiry dates for TDE certificates, Always Encrypted
--          column master keys, TLS endpoint certificates, and SQL login
--          passwords. SQL Server exposes cert expiry directly — no
--          openssl needed.
-- Sources: sys.certificates, sys.symmetric_keys, sys.asymmetric_keys,
--          sys.column_master_keys, sys.dm_db_encryption_keys,
--          sys.certificates joined per-database via a loop (skipped —
--          per-DB walk requires sysadmin), sys.sql_logins (LOGINPROPERTY).
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

-- ---------------------------------------------------------------------------
-- Certificates in the *current* database — includes TDE cert (if the
-- current DB is master) and any app-level cryptographic assets.
-- ---------------------------------------------------------------------------
SELECT
    DB_NAME()                                             AS database_name,
    c.name                                                AS cert_name,
    c.pvt_key_encryption_type_desc                        AS key_encryption,
    c.issuer_name,
    c.start_date,
    c.expiry_date,
    DATEDIFF(day, SYSUTCDATETIME(), c.expiry_date)        AS days_until_expiry,
    CASE
        WHEN c.expiry_date < SYSUTCDATETIME() THEN 'EXPIRED'
        WHEN c.expiry_date < DATEADD(day, 30, SYSUTCDATETIME()) THEN 'expiring within 30 days'
        WHEN c.expiry_date < DATEADD(day, 90, SYSUTCDATETIME()) THEN 'expiring within 90 days'
        ELSE 'ok'
    END                                                   AS expiry_state,
    c.thumbprint
FROM sys.certificates c
ORDER BY c.expiry_date;

-- ---------------------------------------------------------------------------
-- Certificates in master (TDE certs live here). Requires VIEW DEFINITION
-- on master — TRY/CATCH so a restricted audit login does not abort.
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        'master'                                          AS database_name,
        c.name                                            AS cert_name,
        c.pvt_key_encryption_type_desc                    AS key_encryption,
        c.start_date,
        c.expiry_date,
        DATEDIFF(day, SYSUTCDATETIME(), c.expiry_date)    AS days_until_expiry,
        CASE
            WHEN c.expiry_date < SYSUTCDATETIME() THEN 'EXPIRED'
            WHEN c.expiry_date < DATEADD(day, 30, SYSUTCDATETIME()) THEN 'expiring within 30 days'
            WHEN c.expiry_date < DATEADD(day, 90, SYSUTCDATETIME()) THEN 'expiring within 90 days'
            ELSE 'ok'
        END                                               AS expiry_state
    FROM master.sys.certificates c
    ORDER BY c.expiry_date;
END TRY
BEGIN CATCH
    PRINT '[note] master.sys.certificates not accessible: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Databases encrypted at rest (TDE) + encryption state
-- sys.dm_database_encryption_keys.encryption_state_desc values:
--   0 NO_KEY, 1 UNENCRYPTED, 2 ENCRYPTION_IN_PROGRESS,
--   3 ENCRYPTED, 4 KEY_CHANGE_IN_PROGRESS, 5 DECRYPTION_IN_PROGRESS,
--   6 PROTECTION_CHANGE_IN_PROGRESS
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        DB_NAME(dek.database_id)                          AS database_name,
        dek.encryption_state,
        CASE dek.encryption_state
            WHEN 0 THEN 'NO_KEY'
            WHEN 1 THEN 'UNENCRYPTED'
            WHEN 2 THEN 'ENCRYPTION_IN_PROGRESS'
            WHEN 3 THEN 'ENCRYPTED'
            WHEN 4 THEN 'KEY_CHANGE_IN_PROGRESS'
            WHEN 5 THEN 'DECRYPTION_IN_PROGRESS'
            WHEN 6 THEN 'PROTECTION_CHANGE_IN_PROGRESS'
        END                                               AS encryption_state_desc,
        dek.key_algorithm,
        dek.key_length,
        dek.encryptor_type,
        dek.create_date,
        dek.regenerate_date,
        dek.set_date                                      AS last_key_change,
        dek.opened_date
    FROM sys.dm_database_encryption_keys dek
    ORDER BY database_name;
END TRY
BEGIN CATCH
    PRINT '[note] sys.dm_database_encryption_keys unavailable: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Always Encrypted column master keys — CMK thumbprints point at
-- external key stores (AKV/HSM). The key store is where rotation
-- happens, but the SQL-side metadata tells the operator which keys exist.
-- ---------------------------------------------------------------------------
SELECT
    cmk.name                                              AS cmk_name,
    cmk.key_store_provider_name,
    cmk.key_path,
    cmk.create_date,
    cmk.modify_date,
    DATEDIFF(day, cmk.create_date, SYSUTCDATETIME())      AS age_days
FROM sys.column_master_keys cmk
ORDER BY cmk.name;

SELECT
    cek.name                                              AS cek_name,
    cek.create_date,
    cek.modify_date,
    cekv.encrypted_value,
    cmk.name                                              AS cmk_name
FROM sys.column_encryption_keys cek
LEFT JOIN sys.column_encryption_key_values cekv ON cekv.column_encryption_key_id = cek.column_encryption_key_id
LEFT JOIN sys.column_master_keys cmk            ON cmk.column_master_key_id   = cekv.column_master_key_id
ORDER BY cek.name;

-- ---------------------------------------------------------------------------
-- TLS endpoint certificates — the certificate SQL Server offers on TCP
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        certificate_id,
        name,
        issuer_name,
        subject,
        expiry_date,
        DATEDIFF(day, SYSUTCDATETIME(), expiry_date)      AS days_until_expiry,
        thumbprint
    FROM sys.certificates
    WHERE pvt_key_encryption_type = 'NA'
       OR issuer_name IS NOT NULL;
END TRY
BEGIN CATCH
    PRINT '[note] sys.certificates query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- SQL login password expiry / lockout
-- ---------------------------------------------------------------------------
SELECT
    sl.name                                               AS login_name,
    sl.is_disabled,
    sl.is_policy_checked,
    sl.is_expiration_checked,
    LOGINPROPERTY(sl.name, 'PasswordLastSetTime')                AS password_last_set_time,
    CAST(LOGINPROPERTY(sl.name, 'DaysUntilExpiration') AS INT)   AS days_until_expiration,
    CAST(LOGINPROPERTY(sl.name, 'IsExpired')        AS INT)      AS is_expired,
    CAST(LOGINPROPERTY(sl.name, 'IsMustChange')     AS INT)      AS must_change,
    CAST(LOGINPROPERTY(sl.name, 'IsLocked')         AS INT)      AS is_locked,
    CAST(LOGINPROPERTY(sl.name, 'HistoryLength')    AS INT)      AS history_length
FROM sys.sql_logins sl
ORDER BY days_until_expiration;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
SELECT
    (SELECT COUNT(*) FROM sys.certificates WHERE expiry_date < SYSUTCDATETIME())     AS expired_certs_current_db,
    (SELECT COUNT(*) FROM sys.certificates
      WHERE expiry_date BETWEEN SYSUTCDATETIME() AND DATEADD(day, 30, SYSUTCDATETIME())) AS expiring_30d,
    (SELECT COUNT(*) FROM sys.dm_database_encryption_keys
      WHERE encryption_state = 3)                                                    AS tde_encrypted_dbs,
    (SELECT COUNT(*) FROM sys.sql_logins
      WHERE CAST(LOGINPROPERTY(name, 'IsExpired') AS INT) = 1)                       AS expired_sql_logins;
