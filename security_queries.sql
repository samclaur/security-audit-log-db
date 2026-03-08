-- =============================================
-- Security Audit Log Analysis
-- Google Cybersecurity Capstone Reference
-- Author: Samuel McLaurin
-- =============================================

-- Filter failed login attempts
SELECT
    EventTime,
    LoginName,
    HostName,
    ApplicationName,
    'FAILED LOGIN' AS EventType
FROM sys.dm_exec_sessions
WHERE login_time > DATEADD(HOUR, -24, GETDATE())
  AND status = 'sleeping';

-- Review user permissions
SELECT
    dp.name         AS UserName,
    dp.type_desc    AS UserType,
    o.name          AS ObjectName,
    p.permission_name,
    p.state_desc    AS PermissionState
FROM sys.database_permissions p
JOIN sys.database_principals dp ON p.grantee_principal_id = dp.principal_id
JOIN sys.objects o ON p.major_id = o.object_id
ORDER BY dp.name;

-- Identify users with excessive permissions
SELECT
    m.name          AS MemberName,
    r.name          AS RoleName
FROM sys.database_role_members drm
JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
JOIN sys.database_principals m ON drm.member_principal_id = m.principal_id
WHERE r.name IN ('db_owner', 'sysadmin')
ORDER BY r.name;
GO
