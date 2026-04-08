-- =============================================================================
-- sec_11_role_inheritance_chains.sql
-- Priority: MEDIUM
-- Purpose: Visualize role membership graph and find complex / deep
--          inheritance chains that obscure effective privileges.
-- Read-only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Direct role membership (single hop)
-- ---------------------------------------------------------------------------
SELECT
    r.rolname                                            AS member,
    g.rolname                                            AS member_of,
    am.admin_option                                      AS with_admin,
    r.rolinherit                                         AS member_inherits
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.member
JOIN pg_roles g ON g.oid = am.roleid
ORDER BY r.rolname, g.rolname;

-- ---------------------------------------------------------------------------
-- Full transitive role chain (recursive)
-- Shows every role each user effectively becomes a member of.
-- ---------------------------------------------------------------------------
WITH RECURSIVE chain AS (
    SELECT
        r.oid                                            AS user_oid,
        r.rolname                                        AS user,
        g.oid                                            AS role_oid,
        g.rolname                                        AS effective_role,
        1                                                AS depth,
        r.rolname || ' -> ' || g.rolname                 AS path
    FROM pg_auth_members am
    JOIN pg_roles r ON r.oid = am.member
    JOIN pg_roles g ON g.oid = am.roleid
    WHERE r.rolcanlogin
    UNION
    SELECT
        c.user_oid,
        c.user,
        g.oid,
        g.rolname,
        c.depth + 1,
        c.path || ' -> ' || g.rolname
    FROM chain c
    JOIN pg_auth_members am ON am.member = c.role_oid
    JOIN pg_roles g         ON g.oid = am.roleid
    WHERE c.depth < 10
)
SELECT
    user,
    effective_role,
    depth,
    path
FROM chain
ORDER BY user, depth, effective_role;

-- ---------------------------------------------------------------------------
-- Users with the most effective role memberships (complexity hot spots)
-- ---------------------------------------------------------------------------
WITH RECURSIVE chain AS (
    SELECT r.oid AS user_oid, r.rolname AS user, g.oid AS role_oid, 1 AS depth
    FROM pg_auth_members am
    JOIN pg_roles r ON r.oid = am.member
    JOIN pg_roles g ON g.oid = am.roleid
    WHERE r.rolcanlogin
    UNION
    SELECT c.user_oid, c.user, g.oid, c.depth + 1
    FROM chain c
    JOIN pg_auth_members am ON am.member = c.role_oid
    JOIN pg_roles g         ON g.oid = am.roleid
    WHERE c.depth < 10
)
SELECT
    user,
    count(DISTINCT role_oid)                             AS effective_roles,
    max(depth)                                           AS max_depth
FROM chain
GROUP BY user
ORDER BY effective_roles DESC, max_depth DESC;

-- ---------------------------------------------------------------------------
-- Roles with NOINHERIT (must use SET ROLE explicitly to gain privileges)
-- ---------------------------------------------------------------------------
SELECT
    rolname                                              AS role,
    rolcanlogin
FROM pg_roles
WHERE NOT rolinherit
  AND rolname NOT LIKE 'pg\_%' ESCAPE '\'
ORDER BY rolname;

-- ---------------------------------------------------------------------------
-- Cyclic role membership detection (should always return zero rows)
-- ---------------------------------------------------------------------------
WITH RECURSIVE walk AS (
    SELECT roleid, member, ARRAY[member] AS visited
    FROM pg_auth_members
    UNION ALL
    SELECT am.roleid, w.member, w.visited || am.member
    FROM walk w
    JOIN pg_auth_members am ON am.member = w.roleid
    WHERE NOT am.roleid = ANY(w.visited)
      AND array_length(w.visited, 1) < 20
)
SELECT
    pg_get_userbyid(member)                              AS member,
    pg_get_userbyid(roleid)                              AS cycles_back_to,
    array_length(visited, 1)                             AS cycle_length
FROM walk
WHERE member = roleid;
