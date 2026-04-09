-- =============================================================================
-- sec_11_role_inheritance_chains.sql
-- Priority: MEDIUM
-- Purpose: Visualize role membership graph and find complex / deep
--          inheritance chains that obscure effective privileges.
-- Read-only.
-- =============================================================================

-- NOTE: MySQL roles were introduced in MySQL 8.0. Role membership is stored
--       in mysql.role_edges (direct) and mysql.default_roles (auto-activated).
--       MySQL does not support recursive role inheritance (roles within roles
--       are allowed one level deep in practice, though the engine supports
--       deeper nesting). There is no cyclic-membership guard in older versions.
--       NOINHERIT (PostgreSQL) has no direct equivalent; in MySQL, a role
--       that is not in default_roles must be SET ROLE explicitly.

-- ---------------------------------------------------------------------------
-- Direct role membership (single hop)
-- ---------------------------------------------------------------------------
SELECT
    re.FROM_USER                                            AS role,
    re.FROM_HOST                                            AS role_host,
    re.TO_USER                                              AS member,
    re.TO_HOST                                              AS member_host,
    re.WITH_ADMIN_OPTION                                    AS with_admin,
    CASE WHEN dr.DEFAULT_ROLE_USER IS NOT NULL
         THEN 'YES (auto-activated)'
         ELSE 'NO (requires SET ROLE)'
    END                                                     AS auto_activated
FROM mysql.role_edges re
LEFT JOIN mysql.default_roles dr
  ON  dr.USER              = re.TO_USER
  AND dr.HOST              = re.TO_HOST
  AND dr.DEFAULT_ROLE_USER = re.FROM_USER
  AND dr.DEFAULT_ROLE_HOST = re.FROM_HOST
ORDER BY re.FROM_USER, re.TO_USER;

-- ---------------------------------------------------------------------------
-- Full transitive role chain (recursive CTE — MySQL 8.0+)
-- Shows every role each login account effectively belongs to.
-- ---------------------------------------------------------------------------
WITH RECURSIVE chain AS (
    -- Base: direct role memberships for login accounts
    SELECT
        re.TO_USER                                          AS account,
        re.TO_HOST                                          AS account_host,
        re.FROM_USER                                        AS effective_role,
        re.FROM_HOST                                        AS role_host,
        1                                                   AS depth,
        CONCAT(re.TO_USER, ' -> ', re.FROM_USER)            AS path
    FROM mysql.role_edges re
    JOIN mysql.user u
      ON  u.User = re.TO_USER
      AND u.Host = re.TO_HOST
      AND u.account_locked = 'N'    -- login accounts only

    UNION ALL

    -- Recursive: roles granted to roles
    SELECT
        c.account,
        c.account_host,
        re.FROM_USER,
        re.FROM_HOST,
        c.depth + 1,
        CONCAT(c.path, ' -> ', re.FROM_USER)
    FROM chain c
    JOIN mysql.role_edges re
      ON  re.TO_USER = c.effective_role
      AND re.TO_HOST = c.role_host
    WHERE c.depth < 10
)
SELECT
    account,
    effective_role,
    depth,
    path
FROM chain
ORDER BY account, depth, effective_role;

-- ---------------------------------------------------------------------------
-- Accounts with the most effective role memberships (complexity hot spots)
-- ---------------------------------------------------------------------------
WITH RECURSIVE chain AS (
    SELECT
        re.TO_USER                                          AS account,
        re.TO_HOST                                          AS account_host,
        re.FROM_USER                                        AS effective_role,
        re.FROM_HOST                                        AS role_host,
        1                                                   AS depth
    FROM mysql.role_edges re
    JOIN mysql.user u
      ON  u.User = re.TO_USER
      AND u.Host = re.TO_HOST
      AND u.account_locked = 'N'

    UNION ALL

    SELECT
        c.account,
        c.account_host,
        re.FROM_USER,
        re.FROM_HOST,
        c.depth + 1
    FROM chain c
    JOIN mysql.role_edges re
      ON  re.TO_USER = c.effective_role
      AND re.TO_HOST = c.role_host
    WHERE c.depth < 10
)
SELECT
    account,
    COUNT(DISTINCT effective_role)                          AS effective_roles,
    MAX(depth)                                              AS max_depth
FROM chain
GROUP BY account
ORDER BY effective_roles DESC, max_depth DESC;

-- ---------------------------------------------------------------------------
-- Roles that require explicit SET ROLE (not in default_roles)
-- These are the MySQL equivalent of PostgreSQL NOINHERIT roles —
-- privileges are not automatically activated.
-- ---------------------------------------------------------------------------
SELECT
    re.TO_USER                                              AS member,
    re.TO_HOST,
    re.FROM_USER                                            AS role,
    re.FROM_HOST,
    'Must run: SET ROLE role_name; to activate'            AS note
FROM mysql.role_edges re
WHERE NOT EXISTS (
    SELECT 1
    FROM mysql.default_roles dr
    WHERE dr.USER              = re.TO_USER
      AND dr.HOST              = re.TO_HOST
      AND dr.DEFAULT_ROLE_USER = re.FROM_USER
      AND dr.DEFAULT_ROLE_HOST = re.FROM_HOST
)
ORDER BY re.TO_USER, re.FROM_USER;

-- ---------------------------------------------------------------------------
-- Default roles summary (activated automatically on login)
-- ---------------------------------------------------------------------------
SELECT
    USER,
    HOST,
    GROUP_CONCAT(DEFAULT_ROLE_USER ORDER BY DEFAULT_ROLE_USER SEPARATOR ', ')
                                                            AS default_roles
FROM mysql.default_roles
GROUP BY USER, HOST
ORDER BY USER, HOST;

-- ---------------------------------------------------------------------------
-- Cyclic role membership detection
-- NOTE: MySQL 8.0 prevents direct cycles in role membership.
--       This query serves as an assertion — it should always return zero rows.
-- ---------------------------------------------------------------------------
WITH RECURSIVE walk AS (
    SELECT
        FROM_USER                                           AS role,
        TO_USER                                             AS member,
        CAST(CONCAT(FROM_USER, '->', TO_USER) AS CHAR(2000)) AS visited
    FROM mysql.role_edges
    UNION ALL
    SELECT
        w.role,
        re.TO_USER,
        CAST(CONCAT(w.visited, '->', re.TO_USER) AS CHAR(2000))
    FROM walk w
    JOIN mysql.role_edges re
      ON re.FROM_USER = w.member
    WHERE w.visited NOT LIKE CONCAT('%', re.TO_USER, '%')
      AND CHAR_LENGTH(w.visited) < 500
)
SELECT
    role,
    member                                                  AS cycles_back_to
FROM walk
WHERE role = member;
