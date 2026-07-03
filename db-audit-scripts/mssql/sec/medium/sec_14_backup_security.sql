-- =============================================================================
-- sec_14_backup_security.sql
-- Priority: MEDIUM
-- Purpose: Backup-related access and ongoing backup activity. Covers who
--          can take backups, recent backup history, and whether backups
--          are encrypted.
-- Sources: sys.server_permissions, sys.server_role_members,
--          msdb.dbo.backupset, msdb.dbo.backupmediafamily,
--          sys.dm_exec_requests, sys.availability_replicas.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;  -- read-only audit; avoid taking shared locks on hot objects

-- ---------------------------------------------------------------------------
-- Logins with backup permission (db_backupoperator in each database,
-- sysadmin server-wide, or direct BACKUP permission)
-- ---------------------------------------------------------------------------
SELECT
    r.name                                            AS role_name,
    m.name                                            AS member_name,
    m.type_desc                                       AS member_type
FROM sys.server_role_members srm
JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = srm.member_principal_id
WHERE r.name IN ('sysadmin','dbcreator')
ORDER BY r.name, m.name;

-- db_backupoperator in the current database
SELECT
    DB_NAME()                                         AS database_name,
    r.name                                            AS role,
    m.name                                            AS member,
    m.type_desc
FROM sys.database_role_members drm
JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id
WHERE r.name IN ('db_backupoperator','db_owner')
ORDER BY r.name, m.name;

-- NOTE: every backup query below reads msdb.dbo.backupset /
-- backupmediafamily. msdb is NOT present on Azure SQL Database, so
-- each block is wrapped in TRY/CATCH — the audit keeps going there
-- with a [note] line.

-- ---------------------------------------------------------------------------
-- Last backup per database + encryption status
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        d.name                                        AS database_name,
        d.recovery_model_desc,
        MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END) AS last_full,
        MAX(CASE WHEN bs.type = 'I' THEN bs.backup_finish_date END) AS last_diff,
        MAX(CASE WHEN bs.type = 'L' THEN bs.backup_finish_date END) AS last_log,
        DATEDIFF(hour,
                 ISNULL(MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END),
                        '1900-01-01'),
                 SYSDATETIME())                    AS hours_since_full,
        MAX(CASE WHEN bs.type = 'D' THEN bs.encryptor_type END) AS last_full_encryptor_type
    FROM sys.databases d
    LEFT JOIN msdb.dbo.backupset bs
          ON bs.database_name = d.name
    WHERE d.database_id > 4
    GROUP BY d.name, d.recovery_model_desc
    ORDER BY d.name;
END TRY
BEGIN CATCH
    PRINT '[note] last-backup-per-database query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Unencrypted backup sets (compliance review)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT TOP 100
        bs.database_name,
        bs.type                                       AS backup_type,
        bs.backup_finish_date,
        bs.encryptor_type,
        bs.encryptor_thumbprint,
        bs.key_algorithm,
        bs.is_password_protected,
        bmf.physical_device_name
    FROM msdb.dbo.backupset bs
    JOIN msdb.dbo.backupmediafamily bmf ON bmf.media_set_id = bs.media_set_id
    WHERE bs.encryptor_type IS NULL
    ORDER BY bs.backup_finish_date DESC;
END TRY
BEGIN CATCH
    PRINT '[note] unencrypted-backup-sets query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Recent backup history (last 30 days)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT TOP 100
        bs.database_name,
        bs.type                                       AS backup_type,
        bs.backup_start_date,
        bs.backup_finish_date,
        DATEDIFF(second, bs.backup_start_date, bs.backup_finish_date) AS duration_sec,
        CAST(bs.backup_size / 1024.0 / 1024 AS DECIMAL(18,2)) AS backup_size_mb,
        CAST(bs.compressed_backup_size / 1024.0 / 1024 AS DECIMAL(18,2)) AS compressed_mb,
        bs.user_name                                  AS backed_up_by,
        bmf.physical_device_name
    FROM msdb.dbo.backupset bs
    JOIN msdb.dbo.backupmediafamily bmf ON bmf.media_set_id = bs.media_set_id
    WHERE bs.backup_finish_date >= DATEADD(day, -30, SYSDATETIME())
    ORDER BY bs.backup_finish_date DESC;
END TRY
BEGIN CATCH
    PRINT '[note] recent-backup-history query failed: ' + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Currently running backup / restore operations
-- ---------------------------------------------------------------------------
SELECT
    r.session_id,
    s.login_name,
    DB_NAME(r.database_id)                            AS database_name,
    r.command,
    r.start_time,
    r.percent_complete,
    DATEADD(second, r.estimated_completion_time / 1000, SYSDATETIME())
                                                      AS estimated_completion,
    LEFT(txt.text, 300)                               AS statement_text
FROM sys.dm_exec_requests r
JOIN sys.dm_exec_sessions s ON s.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) txt
WHERE r.command LIKE 'BACKUP%' OR r.command LIKE 'RESTORE%';

-- ---------------------------------------------------------------------------
-- Agent jobs that mention BACKUP (scheduled backup automation)
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        j.name                                        AS job_name,
        j.enabled,
        js.name                                       AS schedule_name,
        SUSER_SNAME(j.owner_sid)                      AS owner,
        j.date_created,
        j.date_modified
    FROM msdb.dbo.sysjobs j
    LEFT JOIN msdb.dbo.sysjobschedules jss ON jss.job_id = j.job_id
    LEFT JOIN msdb.dbo.sysschedules js      ON js.schedule_id = jss.schedule_id
    WHERE j.enabled = 1
      AND EXISTS (
          SELECT 1 FROM msdb.dbo.sysjobsteps s
           WHERE s.job_id = j.job_id
             AND (s.command LIKE '%BACKUP%DATABASE%' OR s.command LIKE '%BACKUP%LOG%')
      )
    ORDER BY j.name;
END TRY
BEGIN CATCH
    PRINT '[note] backup-job inventory failed (msdb may be absent): '
          + ERROR_MESSAGE();
END CATCH;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
BEGIN TRY
    SELECT
        (SELECT COUNT(*) FROM msdb.dbo.backupset
          WHERE backup_finish_date >= DATEADD(day, -7, SYSDATETIME())) AS backups_last_7d,
        (SELECT COUNT(*) FROM msdb.dbo.backupset
          WHERE backup_finish_date >= DATEADD(day, -7, SYSDATETIME())
            AND encryptor_type IS NULL)                                   AS unencrypted_last_7d,
        (SELECT COUNT(*) FROM sys.databases d
          WHERE d.database_id > 4
            AND NOT EXISTS (SELECT 1 FROM msdb.dbo.backupset bs
                             WHERE bs.database_name = d.name
                               AND bs.type = 'D'))                         AS databases_never_backed_up;
END TRY
BEGIN CATCH
    PRINT '[note] backup summary failed (msdb may be absent): '
          + ERROR_MESSAGE();
END CATCH;
