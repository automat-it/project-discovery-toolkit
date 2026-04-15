-- =============================================================================
-- sec_11_role_inheritance_chains.sql
-- Priority: MEDIUM
-- Purpose: Visualise server-role and database-role inheritance graphs.
--          Find deep chains that obscure effective privileges, plus
--          cycles (should never happen but worth verifying).
-- Sources: sys.server_role_members, sys.database_role_members,
--          sys.server_principals, sys.database_principals.
-- Read-only.
-- =============================================================================

SET NOCOUNT ON;

-- ---------------------------------------------------------------------------
-- Direct server-role membership (single hop)
-- ---------------------------------------------------------------------------
SELECT
    r.name                                            AS role_name,
    r.type_desc                                       AS role_type,
    m.name                                            AS member_name,
    m.type_desc                                       AS member_type
FROM sys.server_role_members srm
JOIN sys.server_principals r ON r.principal_id = srm.role_principal_id
JOIN sys.server_principals m ON m.principal_id = srm.member_principal_id
ORDER BY r.name, m.name;

-- ---------------------------------------------------------------------------
-- Full transitive server-role chain (recursive)
-- ---------------------------------------------------------------------------
;WITH server_chain AS (
    SELECT
        srm.member_principal_id                       AS leaf_id,
        srm.member_principal_id                       AS current_id,
        CAST(m.name AS NVARCHAR(MAX))                 AS path,
        1                                             AS depth,
        CAST(',' + CAST(srm.member_principal_id AS NVARCHAR(20)) + ',' AS NVARCHAR(MAX)) AS visited
    FROM sys.server_role_members srm
    JOIN sys.server_principals m ON m.principal_id = srm.member_principal_id
    WHERE m.type IN ('S','U','G')                      -- start from actual logins
    UNION ALL
    SELECT
        sc.leaf_id,
        srm.role_principal_id,
        sc.path + ' -> ' + r.name,
        sc.depth + 1,
        sc.visited + CAST(srm.role_principal_id AS NVARCHAR(20)) + ','
    FROM server_chain sc
    JOIN sys.server_role_members srm
          ON srm.member_principal_id = sc.current_id
    JOIN sys.server_principals r
          ON r.principal_id = srm.role_principal_id
    WHERE sc.depth < 10
      AND sc.visited NOT LIKE '%,' + CAST(srm.role_principal_id AS NVARCHAR(20)) + ',%'
)
SELECT
    SUSER_NAME(leaf_id)                               AS login,
    path                                              AS inheritance_path,
    depth
FROM server_chain
WHERE depth > 1                                        -- skip self
ORDER BY login, depth DESC;

-- ---------------------------------------------------------------------------
-- Logins with the most effective server roles (complexity hot spots)
-- ---------------------------------------------------------------------------
;WITH server_chain AS (
    SELECT srm.member_principal_id AS leaf_id,
           srm.member_principal_id AS current_id,
           1 AS depth,
           CAST(',' + CAST(srm.member_principal_id AS NVARCHAR(20)) + ',' AS NVARCHAR(MAX)) AS visited
    FROM sys.server_role_members srm
    UNION ALL
    SELECT sc.leaf_id,
           srm.role_principal_id,
           sc.depth + 1,
           sc.visited + CAST(srm.role_principal_id AS NVARCHAR(20)) + ','
    FROM server_chain sc
    JOIN sys.server_role_members srm ON srm.member_principal_id = sc.current_id
    WHERE sc.depth < 10
      AND sc.visited NOT LIKE '%,' + CAST(srm.role_principal_id AS NVARCHAR(20)) + ',%'
)
SELECT
    SUSER_NAME(leaf_id)                               AS login,
    COUNT(DISTINCT current_id)                        AS effective_role_count,
    MAX(depth)                                        AS max_depth
FROM server_chain
GROUP BY leaf_id
HAVING MAX(depth) > 1
ORDER BY effective_role_count DESC, max_depth DESC;

-- ---------------------------------------------------------------------------
-- Database role membership chain (current database)
-- ---------------------------------------------------------------------------
;WITH db_chain AS (
    SELECT
        drm.member_principal_id                       AS leaf_id,
        drm.member_principal_id                       AS current_id,
        CAST(m.name AS NVARCHAR(MAX))                 AS path,
        1                                             AS depth,
        CAST(',' + CAST(drm.member_principal_id AS NVARCHAR(20)) + ',' AS NVARCHAR(MAX)) AS visited
    FROM sys.database_role_members drm
    JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id
    WHERE m.type IN ('S','U','G')
    UNION ALL
    SELECT
        dc.leaf_id,
        drm.role_principal_id,
        dc.path + ' -> ' + r.name,
        dc.depth + 1,
        dc.visited + CAST(drm.role_principal_id AS NVARCHAR(20)) + ','
    FROM db_chain dc
    JOIN sys.database_role_members drm ON drm.member_principal_id = dc.current_id
    JOIN sys.database_principals r      ON r.principal_id = drm.role_principal_id
    WHERE dc.depth < 10
      AND dc.visited NOT LIKE '%,' + CAST(drm.role_principal_id AS NVARCHAR(20)) + ',%'
)
SELECT
    USER_NAME(leaf_id)                                AS database_user,
    path                                              AS inheritance_path,
    depth
FROM db_chain
WHERE depth > 1
ORDER BY database_user, depth DESC;

-- ---------------------------------------------------------------------------
-- Cyclic server-role membership detection.
-- We carry an explicit "closed" flag that flips when we would revisit an
-- already-seen role, then surface only closed paths.
-- ---------------------------------------------------------------------------
;WITH walk AS (
    SELECT
        srm.role_principal_id                         AS start_role,
        srm.member_principal_id                       AS at_role,
        CAST(',' + CAST(srm.role_principal_id AS NVARCHAR(20))
             + ',' + CAST(srm.member_principal_id AS NVARCHAR(20)) + ',' AS NVARCHAR(MAX)) AS visited,
        CAST(0 AS BIT)                                AS closed,
        1                                             AS depth
    FROM sys.server_role_members srm
    UNION ALL
    SELECT
        w.start_role,
        srm.member_principal_id,
        w.visited + CAST(srm.member_principal_id AS NVARCHAR(20)) + ',',
        -- Must CAST to BIT so the recursive arm matches the anchor's type.
        CAST(CASE WHEN w.visited LIKE '%,' + CAST(srm.member_principal_id AS NVARCHAR(20)) + ',%'
                  THEN 1 ELSE 0 END AS BIT),
        w.depth + 1
    FROM walk w
    JOIN sys.server_role_members srm
          ON srm.role_principal_id = w.at_role
    WHERE w.closed = 0
      AND w.depth < 20
)
SELECT
    SUSER_NAME(start_role)                            AS start_role,
    SUSER_NAME(at_role)                               AS cycles_back_to,
    depth                                             AS cycle_length
FROM walk
WHERE closed = 1;
