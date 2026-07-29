"""
研判分析 - 认证与授权(RBAC)服务层
======================================
本地账号 + 服务端可撤销会话 + 角色/权限模型。

设计要点:
- 与 incident_service 同库(SQLite),复用其连接/ID/时间/审计工具。
- actor 仍是「用户名字符串」——登录用户名直接成为 incident 侧的 actor,
  现有 owner / handlers / notes.author / audit.actor 逻辑与状态机零改动。
- 权限在 MVP 阶段由代码常量 ROLE_PERMISSIONS 定义(默认拒绝),
  Phase 1 再引入可配置的 permissions 表。
"""
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from werkzeug.security import generate_password_hash, check_password_hash

# 复用 incident_service 的数据层工具,保证单库、单套连接配置
from backend.services.incident_service import (
    _conn, _id, _now, _audit, _json_dumps, _json_loads, DATA_DIR,
)


# ============ 角色与权限(MVP:代码常量,默认拒绝) ============

# code -> (显示名, 说明)
BUILTIN_ROLES: List[Tuple[str, str, str]] = [
    ("admin", "系统管理员", "账号与系统治理,拥有全部权限"),
    ("analyst", "研判人员", "研判告警与应急响应,研判全流程"),
    ("responder", "应急处置人", "承接并执行各应急处置子任务"),
    ("reporter", "上报人", "将安全设备告警填报进平台"),
    ("liaison", "业务关联人", "提交与告警相关的系统信息"),
]

ALL_PERMISSIONS = {
    "alert.view", "alert.create", "alert.edit", "alert.delete", "alert.conclude",
    "alert.status", "alert.assign", "alert.reject", "alert.reopen", "alert.note",
    "alert.entity", "subtask.manage", "subtask.execute", "attachment.write", "export",
    "audit.view", "system.manage", "data.clear",
}

# 权限目录（code, 显示名, 分类）——供「角色-权限」可视化编辑
PERMISSION_CATALOG = [
    ("alert.view", "查看告警", "告警"),
    ("alert.create", "录入告警", "告警"),
    ("alert.edit", "编辑告警", "告警"),
    ("alert.delete", "删除告警", "告警"),
    ("alert.entity", "实体增删", "告警"),
    ("attachment.write", "附件上传/删除", "告警"),
    ("alert.conclude", "研判定性", "研判"),
    ("alert.status", "状态流转", "研判"),
    ("alert.assign", "指派处理人", "研判"),
    ("alert.reject", "驳回重判", "研判"),
    ("alert.reopen", "重新研判", "研判"),
    ("alert.note", "研判记录", "研判"),
    ("subtask.manage", "处置子任务", "应急"),
    ("subtask.execute", "执行本人子任务", "应急"),
    ("export", "数据导出", "系统"),
    ("audit.view", "查看审计", "系统"),
    ("system.manage", "用户/角色管理", "系统"),
    ("data.clear", "清空数据", "系统"),
]

ROLE_PERMISSIONS: Dict[str, set] = {
    "admin": set(ALL_PERMISSIONS),
    # 研判人员：在本人经手或主动认领范围内完成研判全流程与应急协作
    "analyst": {
        "alert.view", "alert.create", "alert.edit", "alert.conclude",
        "alert.status", "alert.assign", "alert.reject", "alert.reopen", "alert.note",
        "alert.entity", "subtask.manage", "attachment.write", "export",
    },
    # 应急处置人：执行处置子任务，并维护本人受指派的告警信息
    "responder": {
        "alert.view", "alert.edit", "alert.note", "alert.entity",
        "subtask.execute", "attachment.write",
    },
    # 上报人：填报告警，并维护本人上报的告警
    "reporter": {
        "alert.view", "alert.create", "alert.edit", "alert.note",
        "alert.entity", "attachment.write",
    },
    # 业务关联人：维护本人经手告警中的记录、实体和附件
    "liaison": {
        "alert.view", "alert.edit", "alert.note", "alert.entity",
        "attachment.write",
    },
}

# ============ 对象级授权（Phase 1：越权收敛） ============
# 仅管理员不受对象级限制（可处理任意告警）；研判人员等均收敛到本人经手范围
SCOPE_BYPASS_ROLES = {"admin"}

# 每个角色对「对象级」权限的归属要求；未列出的权限=该角色拥有即可全局使用。
#   'handler'  需为该告警 owner 或 handlers 成员（研判处理人）
#   'assigned' 需为 handler 或该告警某处置子任务的 assignee（应急处置人语义）
#   'self'     指派类：仅能增删本人（自领/自撤）
ROLE_SCOPES = {
    # 研判人员：业务操作收敛到本人经手范围；指派允许未分派告警或本人经手告警选择有效账号
    "analyst": {
        "alert.view": "handler",
        "alert.edit": "handler",
        "alert.conclude": "handler",
        "alert.status": "handler",
        "alert.entity": "handler",
        "attachment.write": "handler",
        "subtask.manage": "handler",
        "alert.reject": "handler",
        "alert.reopen": "handler",
        "alert.assign": "handler",
        "alert.note": "handler",
    },
    # 应急处置人：只能看/处置受指派（本人为处理人或某处置子任务的执行人）的告警
    "responder": {
        "alert.view": "assigned",
        "alert.edit": "assigned",
        "alert.note": "assigned",
        "alert.entity": "assigned",
        "attachment.write": "assigned",
        "subtask.execute": "assigned",
    },
    # 上报人：只能查看和维护本人上报（创建者=经手人）的告警；新建不受限
    "reporter": {
        "alert.view": "handler",
        "alert.note": "handler",
        "alert.entity": "handler",
        "attachment.write": "handler",
        "alert.edit": "handler",
    },
    # 业务关联人：只能查看和维护本人经手的告警
    "liaison": {
        "alert.edit": "handler",
        "alert.view": "handler",
        "alert.note": "handler",
        "alert.entity": "handler",
        "attachment.write": "handler",
    },
    # admin：对象级豁免（可处理任意告警）
}

# 归属宽松度排序：assigned ⊇ handler ⊇ self
_SCOPE_RANK = {"self": 0, "handler": 1, "assigned": 2}

# ============ 策略常量 ============

RESOURCE_SCOPED_PERMISSIONS = {
    "alert.view", "alert.edit", "alert.delete", "alert.conclude", "alert.status",
    "alert.assign", "alert.reject", "alert.reopen", "alert.note", "alert.entity",
    "subtask.manage", "subtask.execute", "attachment.write",
}
ROLE_DEFAULT_SCOPES = {
    "analyst": "handler",
    "responder": "assigned",
    "reporter": "handler",
    "liaison": "handler",
}
ADMIN_ONLY_PERMISSIONS = {"alert.delete", "system.manage", "data.clear"}
MIN_PASSWORD_LEN = 12
# 登录失败锁定策略：连续失败达到阈值后临时锁定账号，防止暴力破解。
LOGIN_FAILURE_THRESHOLD = 8
LOGIN_LOCK_MINUTES = 15
SESSION_IDLE_MINUTES = 60
SESSION_ABSOLUTE_HOURS = 12
# 会话最近活跃时间的写入节流阈值（秒）：并发页面加载时避免每个请求都写库抢锁。
_LAST_SEEN_THROTTLE_SECONDS = 30
VALID_STATUSES = {"active", "disabled"}
SECRET_KEY_FILE = DATA_DIR / "secret_key"

# 服务令牌只允许「入库类」低危权限，杜绝令牌被授予删除/清空/管理等能力
INGEST_TOKEN_SCOPES = {"alert.create", "alert.view", "attachment.write", "alert.note"}
API_TOKEN_PREFIX = "svc_"


# ============ 工具 ============

def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        result = datetime.fromisoformat(text)
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _role_perm_map() -> Dict[str, set]:
    """角色→权限集（DB 为准；表空时回退代码常量）。admin 恒拥有全部权限,防管理锁死。"""
    with _conn() as conn:
        rows = conn.execute("SELECT role_code, permission_code FROM role_permissions").fetchall()
    m: Dict[str, set] = {}
    for r in rows:
        m.setdefault(r["role_code"], set()).add(r["permission_code"])
    if not m:
        m = {k: set(v) for k, v in ROLE_PERMISSIONS.items()}
    m.setdefault("admin", set()).update(ALL_PERMISSIONS)
    return m


def permissions_for_roles(role_codes: List[str]) -> List[str]:
    m = _role_perm_map()
    perms: set = set()
    for code in role_codes:
        perms |= m.get(code, set())
    return sorted(perms)


def list_permission_catalog() -> List[Dict[str, str]]:
    return [{"code": c, "name": n, "category": cat} for c, n, cat in PERMISSION_CATALOG]


def get_role_permissions() -> Dict[str, List[str]]:
    """返回每个角色当前的权限列表（供角色-权限矩阵展示）。"""
    m = _role_perm_map()
    return {code: sorted(m.get(code, set())) for code, _, _ in BUILTIN_ROLES}


def set_role_permissions(role_code: str, perms: List[str], actor: str) -> Dict[str, List[str]]:
    if role_code == "admin":
        raise ValueError("管理员角色的权限不可修改（始终拥有全部权限）")
    if role_code not in {code for code, _, _ in BUILTIN_ROLES}:
        raise ValueError("角色不存在")
    requested = list(dict.fromkeys(str(p).strip() for p in (perms or []) if str(p).strip()))
    unknown = [p for p in requested if p not in ALL_PERMISSIONS]
    if unknown:
        raise ValueError("包含未知权限：" + "、".join(unknown))
    forbidden = sorted(set(requested) & ADMIN_ONLY_PERMISSIONS)
    if forbidden:
        raise ValueError("以下高风险权限仅允许管理员角色持有：" + "、".join(forbidden))
    clean = requested
    with _conn() as conn:
        conn.execute("DELETE FROM role_permissions WHERE role_code = ?", (role_code,))
        for p in clean:
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions (role_code, permission_code) VALUES (?, ?)",
                (role_code, p),
            )
    _audit("set_role_permissions", "role", role_code, actor, after={"permissions": clean})
    return get_role_permissions()


def _user_role_codes(user: Dict[str, Any]) -> List[str]:
    return [r.get("code") for r in (user or {}).get("roles", []) if r.get("code")]


def has_scope_bypass(user: Dict[str, Any]) -> bool:
    return any(code in SCOPE_BYPASS_ROLES for code in _user_role_codes(user))


def effective_scope(user: Dict[str, Any], permission: str) -> Optional[str]:
    """返回对象级归属要求；None 表示该权限不受对象归属限制。

    管理员全局放行；服务令牌和普通角色的对象权限默认收敛到经手/受指派范围。
    """
    if has_scope_bypass(user):
        return None
    if (user or {}).get("is_service"):
        return "handler" if permission in RESOURCE_SCOPED_PERMISSIONS else None
    role_codes = _user_role_codes(user)
    perm_map = _role_perm_map()
    holding = [c for c in role_codes if permission in perm_map.get(c, set())]
    if not holding:
        return None  # 无该权限（require_perm 已在上游拦截，这里保守放行给上游处理）
    scopes = []
    for code in holding:
        sc = ROLE_SCOPES.get(code, {}).get(permission)
        if sc is None and permission in RESOURCE_SCOPED_PERMISSIONS:
            sc = ROLE_DEFAULT_SCOPES.get(code, "handler")
        if sc is None:
            return None  # 有角色无限制地授予 -> 全局放行
        scopes.append(sc)
    return max(scopes, key=lambda s: _SCOPE_RANK.get(s, 0))


# ============ 告警队列读可见性（按角色，与写权限/对象级作用域相互独立） ============
# all           = 看全部（管理员）
# own+unassigned= 本人经手 + 待分配(无处理人) 告警（研判人员可主动认领）
# own           = 仅本人经手/受指派的告警（研判人员/业务关联人/应急处置人）
QUEUE_SEE_ALL_ROLES = {"admin"}
# 研判人员除本人经手外，还能看待分配告警，以便主动认领。
QUEUE_SEE_UNASSIGNED_ROLES = {"analyst", "reporter"}


def queue_visibility(user: Dict[str, Any]) -> str:
    roles = set(_user_role_codes(user))
    if roles & QUEUE_SEE_ALL_ROLES:
        return "all"
    if roles & QUEUE_SEE_UNASSIGNED_ROLES:
        return "own+unassigned"
    return "own"


def ensure_secret_key() -> str:
    """持久化随机 Flask SECRET_KEY;缺失则生成并落盘(而非硬编码)。"""
    if SECRET_KEY_FILE.exists():
        key = SECRET_KEY_FILE.read_text(encoding="utf-8").strip()
        if key:
            return key
    key = secrets.token_hex(32)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SECRET_KEY_FILE.write_text(key, encoding="utf-8")
    return key


# ============ 建表 / 初始化 ============

def init_auth() -> None:
    with _conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                must_change_password INTEGER NOT NULL DEFAULT 0,
                failed_login_count INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                email TEXT,
                phone TEXT,
                last_login_at TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                is_system INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS user_roles (
                user_id TEXT NOT NULL,
                role_id TEXT NOT NULL,
                granted_by TEXT,
                granted_at TEXT NOT NULL,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                csrf_hash TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS api_tokens (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                token_prefix TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL,
                created_by TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                expires_at TEXT,
                revoked INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS permissions (
                code TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT
            );

            CREATE TABLE IF NOT EXISTS role_permissions (
                role_code TEXT NOT NULL,
                permission_code TEXT NOT NULL,
                PRIMARY KEY (role_code, permission_code)
            );

            CREATE TABLE IF NOT EXISTS auth_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
            CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
            """
        )
        # 权限目录：始终与代码定义对齐（名称/分类可更新）
        session_columns = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if "csrf_hash" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN csrf_hash TEXT")
        for code, name, category in PERMISSION_CATALOG:
            conn.execute(
                "INSERT INTO permissions (code, name, category) VALUES (?, ?, ?) "
                "ON CONFLICT(code) DO UPDATE SET name = excluded.name, category = excluded.category",
                (code, name, category),
            )
        # 角色-权限：仅当表为空（首次初始化）时用代码常量播种，之后以管理员的编辑为准
        seeded = conn.execute("SELECT count(*) AS c FROM role_permissions").fetchone()["c"]
        if not seeded:
            for role_code, perms in ROLE_PERMISSIONS.items():
                for perm in perms:
                    conn.execute(
                        "INSERT OR IGNORE INTO role_permissions (role_code, permission_code) VALUES (?, ?)",
                        (role_code, perm),
                    )
        policy_row = conn.execute(
            "SELECT value FROM auth_meta WHERE key = 'permission_policy_version'"
        ).fetchone()
        policy_version = int(policy_row["value"]) if policy_row else 0
        if policy_version < 2:
            placeholders = ",".join("?" for _ in ADMIN_ONLY_PERMISSIONS)
            conn.execute(
                f"DELETE FROM role_permissions WHERE role_code != 'admin' "
                f"AND permission_code IN ({placeholders})",
                tuple(sorted(ADMIN_ONLY_PERMISSIONS)),
            )
            policy_version = 2
        if policy_version < 3:
            conn.execute(
                "DELETE FROM role_permissions WHERE role_code = 'responder' AND permission_code = 'subtask.manage'"
            )
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions (role_code, permission_code) VALUES ('responder', 'subtask.execute')"
            )
            policy_version = 3
        if policy_version < 4:
            conn.execute("DELETE FROM role_permissions WHERE permission_code = 'ocr.run'")
            conn.execute("DELETE FROM permissions WHERE code = 'ocr.run'")
            policy_version = 4
        conn.execute(
            "INSERT OR REPLACE INTO auth_meta (key, value) VALUES ('permission_policy_version', ?)",
            (str(policy_version),),
        )
        now = _now()
        for code, name, description in BUILTIN_ROLES:
            existing = conn.execute("SELECT id FROM roles WHERE code = ?", (code,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE roles SET name = ?, description = ? WHERE code = ?",
                    (name, description, code),
                )
            else:
                conn.execute(
                    "INSERT INTO roles (id, code, name, description, is_system) VALUES (?, ?, ?, ?, 1)",
                    (_id("rol_"), code, name, description),
                )
        _ = now
        # —— 迁移到新角色模型（一次性、幂等）：清理弃用角色 + 重刷内置角色-权限 ——
        builtin_codes = {c for c, _n, _d in BUILTIN_ROLES}
        legacy = {r["code"] for r in conn.execute("SELECT code FROM roles").fetchall()} - builtin_codes
        legacy |= {r["role_code"] for r in conn.execute("SELECT DISTINCT role_code FROM role_permissions").fetchall()} - builtin_codes
        if legacy:
            for code in sorted(legacy):
                row = conn.execute("SELECT id FROM roles WHERE code = ?", (code,)).fetchone()
                if row:
                    conn.execute("DELETE FROM user_roles WHERE role_id = ?", (row["id"],))
                    conn.execute("DELETE FROM roles WHERE code = ?", (code,))
                conn.execute("DELETE FROM role_permissions WHERE role_code = ?", (code,))
            # 角色模型变更：把内置角色的角色-权限重置为代码定义（覆盖旧默认，仅本次迁移执行）
            for role_code, perms in ROLE_PERMISSIONS.items():
                conn.execute("DELETE FROM role_permissions WHERE role_code = ?", (role_code,))
                for perm in perms:
                    conn.execute(
                        "INSERT OR IGNORE INTO role_permissions (role_code, permission_code) VALUES (?, ?)",
                        (role_code, perm),
                    )


def _role_id(conn, code: str) -> Optional[str]:
    row = conn.execute("SELECT id FROM roles WHERE code = ?", (code,)).fetchone()
    return row["id"] if row else None


def list_roles() -> List[Dict[str, Any]]:
    init_auth()
    with _conn() as conn:
        rows = conn.execute("SELECT code, name, description FROM roles ORDER BY code").fetchall()
    return [dict(r) for r in rows]


# ============ 用户读取 ============

def _get_user_row_by_username(username: str):
    with _conn() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

def is_active_username(username: str) -> bool:
    row = _get_user_row_by_username((username or "").strip())
    return bool(row and row["status"] == "active")


def _roles_of(user_id: str) -> List[Dict[str, str]]:
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT r.code AS code, r.name AS name
            FROM user_roles ur JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = ?
            ORDER BY r.code
            """,
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    """返回带角色与权限的用户视图(permissions 为 set,便于鉴权判定)。"""
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None
    roles = _roles_of(user_id)
    role_codes = [r["code"] for r in roles]
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"] or row["username"],
        "status": row["status"],
        "must_change_password": bool(row["must_change_password"]),
        "last_login_at": row["last_login_at"],
        "created_at": row["created_at"],
        "roles": roles,
        "permissions": set(permissions_for_roles(role_codes)),
    }


def list_users() -> List[Dict[str, Any]]:
    init_auth()
    with _conn() as conn:
        rows = conn.execute("SELECT id FROM users ORDER BY created_at ASC").fetchall()
    users = []
    for r in rows:
        u = get_user(r["id"])
        if u:
            u = dict(u)
            u["permissions"] = sorted(u["permissions"])
            users.append(u)
    return users


def list_directory(role_code: Optional[str] = None) -> List[Dict[str, Any]]:
    """指派选人用的精简用户目录：仅活跃账号、用户名与显示名。"""
    out = []
    for u in list_users():
        if u.get("status") != "active":
            continue
        codes = [r["code"] for r in u.get("roles", [])]
        if role_code and role_code not in codes:
            continue
        out.append({
            "username": u["username"],
            "display_name": u["display_name"],
        })
    return out


def _count_active_admins(exclude_user_id: Optional[str] = None) -> int:
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT u.id AS id
            FROM users u
            JOIN user_roles ur ON ur.user_id = u.id
            JOIN roles r ON r.id = ur.role_id
            WHERE r.code = 'admin' AND u.status = 'active'
            """
        ).fetchall()
    ids = {r["id"] for r in rows}
    if exclude_user_id:
        ids.discard(exclude_user_id)
    return len(ids)


# ============ 用户写入 ============

def _validate_roles(role_codes: List[str]) -> List[str]:
    known = {code for code, _, _ in BUILTIN_ROLES}
    clean = []
    for code in role_codes or []:
        code = str(code).strip()
        if code and code in known and code not in clean:
            clean.append(code)
    if not clean:
        raise ValueError("至少需要指定一个有效角色")
    return clean


def create_user(
    username: str,
    password: str,
    display_name: str = "",
    role_codes: Optional[List[str]] = None,
    actor: str = "system",
    must_change: bool = True,
) -> Dict[str, Any]:
    init_auth()
    username = (username or "").strip()
    if not username:
        raise ValueError("用户名不能为空")
    if len(password or "") < MIN_PASSWORD_LEN:
        raise ValueError(f"口令长度至少 {MIN_PASSWORD_LEN} 位")
    role_codes = _validate_roles(role_codes or [])
    if _get_user_row_by_username(username):
        raise ValueError("用户名已存在")

    user_id = _id("usr_")
    now = _now()
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO users
            (id, username, display_name, password_hash, status, must_change_password,
             failed_login_count, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', ?, 0, ?, ?, ?)
            """,
            (
                user_id, username, display_name or username,
                generate_password_hash(password), 1 if must_change else 0,
                actor, now, now,
            ),
        )
        for code in role_codes:
            rid = _role_id(conn, code)
            if rid:
                conn.execute(
                    "INSERT OR IGNORE INTO user_roles (user_id, role_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
                    (user_id, rid, actor, now),
                )
    _audit("create_user", "user", user_id, actor, after={"username": username, "roles": role_codes})
    result = get_user(user_id)
    result["permissions"] = sorted(result["permissions"])
    return result


def set_user_roles(user_id: str, role_codes: List[str], actor: str) -> Dict[str, Any]:
    role_codes = _validate_roles(role_codes)
    target = get_user(user_id)
    if not target:
        raise ValueError("用户不存在")
    had_admin = any(r["code"] == "admin" for r in target["roles"])
    if had_admin and "admin" not in role_codes and _count_active_admins(exclude_user_id=user_id) == 0:
        raise ValueError("不能移除最后一个管理员的 admin 角色")
    now = _now()
    with _conn() as conn:
        conn.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
        for code in role_codes:
            rid = _role_id(conn, code)
            if rid:
                conn.execute(
                    "INSERT OR IGNORE INTO user_roles (user_id, role_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
                    (user_id, rid, actor, now),
                )
        conn.execute("UPDATE users SET updated_at = ? WHERE id = ?", (now, user_id))
    _audit("set_user_roles", "user", user_id, actor,
           before={"roles": [r["code"] for r in target["roles"]]}, after={"roles": role_codes})
    # 改角色即让该用户所有会话失效,强制重新登录以刷新权限
    _revoke_user_sessions(user_id)
    result = get_user(user_id)
    result["permissions"] = sorted(result["permissions"])
    return result


def set_user_status(user_id: str, status: str, actor: str) -> Dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError("状态值无效")
    target = get_user(user_id)
    if not target:
        raise ValueError("用户不存在")
    is_admin = any(r["code"] == "admin" for r in target["roles"])
    if is_admin and status != "active" and _count_active_admins(exclude_user_id=user_id) == 0:
        raise ValueError("不能停用最后一个可用的管理员")
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET status = ?, locked_until = NULL, failed_login_count = 0, updated_at = ? WHERE id = ?",
            (status, _now(), user_id),
        )
    _audit("set_user_status", "user", user_id, actor, after={"status": status})
    if status != "active":
        _revoke_user_sessions(user_id)
    result = get_user(user_id)
    result["permissions"] = sorted(result["permissions"])
    return result


def admin_reset_password(user_id: str, new_password: str, actor: str) -> None:
    target = get_user(user_id)
    if not target:
        raise ValueError("用户不存在")
    if len(new_password or "") < MIN_PASSWORD_LEN:
        raise ValueError(f"口令长度至少 {MIN_PASSWORD_LEN} 位")
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 1, status = 'active', "
            "locked_until = NULL, failed_login_count = 0, updated_at = ? WHERE id = ?",
            (generate_password_hash(new_password), _now(), user_id),
        )
    _audit("admin_reset_password", "user", user_id, actor)
    _revoke_user_sessions(user_id)


def change_password(user_id: str, old_password: str, new_password: str) -> Tuple[bool, Optional[str]]:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return False, "用户不存在"
    if not check_password_hash(row["password_hash"], old_password or ""):
        return False, "原口令不正确"
    if len(new_password or "") < MIN_PASSWORD_LEN:
        return False, f"新口令长度至少 {MIN_PASSWORD_LEN} 位"
    if check_password_hash(row["password_hash"], new_password):
        return False, "新口令不能与原口令相同"
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = ? WHERE id = ?",
            (generate_password_hash(new_password), _now(), user_id),
        )
    _audit("change_password", "user", user_id, row["username"])
    _revoke_user_sessions(user_id)
    return True, None


# ============ 登录 ============
# 失败计数 + 临时锁定：达到阈值后锁定账号一段时间，防止暴力破解。
# 锁定按账号，不按 IP（口令喷洒攻击者会换 IP）；失败 IP 仍记入审计以便排查。

def _register_failure(user_row, ip: str) -> None:
    """递增失败计数，达到阈值时设置锁定到期时间。"""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET failed_login_count = failed_login_count + 1, updated_at = ? WHERE id = ?",
            (now_iso, user_row["id"]),
        )
        row = conn.execute(
            "SELECT failed_login_count FROM users WHERE id = ?", (user_row["id"],)
        ).fetchone()
    count = row["failed_login_count"] if row else 0
    locked = count >= LOGIN_FAILURE_THRESHOLD
    if locked:
        lock_until = (now + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
        with _conn() as conn:
            conn.execute(
                "UPDATE users SET locked_until = ?, updated_at = ? WHERE id = ?",
                (lock_until, now_iso, user_row["id"]),
            )
    _audit("login_failed", "auth", user_row["id"], user_row["username"],
           after={"ip": ip, "failed_count": count, "locked": locked})


def _register_success(user_id: str) -> None:
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET last_login_at = ?, failed_login_count = 0, "
            "locked_until = NULL, updated_at = ? WHERE id = ?",
            (_now(), _now(), user_id),
        )


def verify_login(username: str, password: str, ip: str = "", user_agent: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    init_auth()
    username = (username or "").strip()
    if not username or not password:
        return None, "请输入用户名和口令"
    row = _get_user_row_by_username(username)
    if not row:
        _audit("login_failed", "auth", username, username, after={"reason": "no_such_user", "ip": ip})
        return None, "用户名或口令错误"
    if row["status"] == "disabled":
        _audit("login_failed", "auth", row["id"], username, after={"reason": "disabled", "ip": ip})
        return None, "账号已停用,请联系管理员"
    # 检查临时锁定
    locked_until = _parse_dt(row["locked_until"])
    if locked_until and datetime.now(timezone.utc) < locked_until:
        remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds() // 60) + 1
        _audit("login_failed", "auth", row["id"], username,
               after={"reason": "locked", "ip": ip, "locked_until": row["locked_until"]})
        return None, f"账号已锁定，请约 {remaining} 分钟后重试"
    if not check_password_hash(row["password_hash"], password):
        _register_failure(row, ip)
        # 锁定后重新读取以判断是否刚触发
        fresh = _get_user_row_by_username(username)
        if fresh and fresh["locked_until"]:
            return None, "登录失败次数过多，账号已被临时锁定"
        return None, "用户名或口令错误"
    _register_success(row["id"])
    _audit("login", "auth", row["id"], username, after={"ip": ip})
    return get_user(row["id"]), None


# ============ 会话 ============

def create_session(user_id: str, ip: str = "", user_agent: str = "") -> Dict[str, Any]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=SESSION_ABSOLUTE_HOURS)
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO sessions (token, user_id, created_at, last_seen_at, expires_at, ip, user_agent, csrf_hash, revoked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (_hash_token(token), user_id, now.isoformat(), now.isoformat(), expires.isoformat(), ip, (user_agent or "")[:300], _hash_token(csrf)),
        )
    # CSRF 明文仅返回给上层写 cookie，库中保存摘要并与会话绑定。
    return {"token": token, "csrf": csrf, "expires_at": expires.isoformat()}


def resolve_session(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    token_digest = _hash_token(token)
    now = datetime.now(timezone.utc)
    # 只读事务读取会话，尽早释放共享锁；不要在同一事务里 SELECT 后再 UPDATE，
    # 否则并发请求会「各持共享锁、又都想升独占锁」相互阻塞。
    with _conn() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token_digest,)).fetchone()
    if not row or row["revoked"]:
        return None
    expires = _parse_dt(row["expires_at"])
    last_seen = _parse_dt(row["last_seen_at"])
    if (expires and now >= expires) or (
        last_seen and (now - last_seen) > timedelta(minutes=SESSION_IDLE_MINUTES)
    ):
        # 过期/空闲超时：尽力吊销并拒绝（写失败也一律拒绝，安全侧默认拒绝）。
        try:
            with _conn() as conn:
                conn.execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (token_digest,))
        except sqlite3.OperationalError:
            pass
        return None
    user = get_user(row["user_id"])
    if not user or user["status"] != "active":
        return None
    # 刷新最近活跃时间：节流（避免每个请求都写库）+ 尽力而为（锁争用时跳过而非 500）。
    if (not last_seen) or (now - last_seen).total_seconds() >= _LAST_SEEN_THROTTLE_SECONDS:
        try:
            with _conn() as conn:
                conn.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE token = ?",
                    (now.isoformat(), token_digest),
                )
        except sqlite3.OperationalError:
            pass
    return user


def revoke_session(token: str, actor: Optional[str] = None) -> None:
    if not token:
        return
    with _conn() as conn:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE token = ?", (_hash_token(token),))
    if actor:
        _audit("logout", "auth", None, actor)


def verify_session_csrf(token: str, csrf: str) -> bool:
    if not token or not csrf:
        return False
    with _conn() as conn:
        row = conn.execute(
            "SELECT csrf_hash, revoked FROM sessions WHERE token = ?", (_hash_token(token),)
        ).fetchone()
    if not row or row["revoked"] or not row["csrf_hash"]:
        return False
    return secrets.compare_digest(row["csrf_hash"], _hash_token(csrf))

def _revoke_user_sessions(user_id: str) -> None:
    with _conn() as conn:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,))


# ============ 服务令牌（自动化入库） ============

def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _row_to_token(row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "token_prefix": row["token_prefix"],
        "scopes": _json_loads(row["scopes"], []),
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
        "expires_at": row["expires_at"],
        "revoked": bool(row["revoked"]),
    }


def create_api_token(name: str, scopes: List[str], actor: str, expires_days: Optional[int] = None) -> Dict[str, Any]:
    """创建服务令牌；明文令牌仅在此返回一次，库中只存 SHA-256 哈希。"""
    init_auth()
    name = (name or "").strip()
    if not name:
        raise ValueError("令牌名称不能为空")
    clean_scopes = []
    for s in scopes or []:
        s = str(s).strip()
        if s and s in INGEST_TOKEN_SCOPES and s not in clean_scopes:
            clean_scopes.append(s)
    if not clean_scopes:
        raise ValueError("请至少选择一个有效的入库权限（仅允许：%s）" % "、".join(sorted(INGEST_TOKEN_SCOPES)))

    raw = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    token_id = _id("tok_")
    now = _now()
    try:
        valid_days = int(expires_days or 90)
    except (TypeError, ValueError):
        raise ValueError("令牌有效期必须是天数")
    if not 1 <= valid_days <= 3650:
        raise ValueError("令牌有效期必须在 1 到 3650 天之间")
    expires_at = (datetime.now(timezone.utc) + timedelta(days=valid_days)).isoformat()
    with _conn() as conn:
        if conn.execute("SELECT 1 FROM api_tokens WHERE name = ?", (name,)).fetchone():
            raise ValueError("令牌名称已存在，名称不可复用")
        conn.execute(
            """
            INSERT INTO api_tokens
            (id, name, token_prefix, token_hash, scopes, created_by, created_at, expires_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (token_id, name, raw[:12], _hash_token(raw), _json_dumps(clean_scopes), actor, now, expires_at),
        )
    _audit("create_api_token", "api_token", token_id, actor, after={"name": name, "scopes": clean_scopes})
    return {"id": token_id, "name": name, "scopes": clean_scopes, "token": raw, "expires_at": expires_at}


def list_api_tokens() -> List[Dict[str, Any]]:
    init_auth()
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM api_tokens ORDER BY created_at DESC").fetchall()
    return [_row_to_token(r) for r in rows]


def revoke_api_token(token_id: str, actor: str) -> bool:
    with _conn() as conn:
        cur = conn.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ? AND revoked = 0", (token_id,))
        changed = cur.rowcount > 0
    if changed:
        _audit("revoke_api_token", "api_token", token_id, actor)
    return changed


def resolve_api_token(raw: str) -> Optional[Dict[str, Any]]:
    """校验服务令牌，返回服务主体（is_service=True，permissions=令牌 scopes）。"""
    if not raw or not raw.startswith(API_TOKEN_PREFIX):
        return None
    now = datetime.now(timezone.utc)
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_tokens WHERE token_hash = ?", (_hash_token(raw),)
        ).fetchone()
        if not row or row["revoked"]:
            return None
        expires = _parse_dt(row["expires_at"])
        if expires and now >= expires:
            return None
        last_used = _parse_dt(row["last_used_at"])
        if not last_used or (now - last_used).total_seconds() >= _LAST_SEEN_THROTTLE_SECONDS:
            conn.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now.isoformat(), row["id"]))
        scopes = _json_loads(row["scopes"], [])
        name = row["name"]
        token_id = row["id"]
    return {
        "id": f"apitoken:{token_id}",
        "username": f"svc:{name}",
        "display_name": f"服务令牌：{name}",
        "is_service": True,
        "status": "active",
        "roles": [],
        "permissions": set(scopes),
        "token_id": token_id,
    }


# ============ 首次启动引导 ============

def bootstrap() -> Optional[str]:
    """确保表结构与内置角色存在;若无任何用户,则创建 admin 并返回一次性随机口令。"""
    init_auth()
    with _conn() as conn:
        count = conn.execute("SELECT count(*) AS c FROM users").fetchone()["c"]
    if count > 0:
        return None
    password = secrets.token_urlsafe(12)
    create_user("admin", password, "系统管理员", ["admin"], actor="system", must_change=True)
    return password


def audit_denied(actor: Optional[str], permission: str, detail: Optional[Dict[str, Any]] = None) -> None:
    """记录一次鉴权拒绝（权限不足）事件,用于问责与异常访问排查。"""
    _audit("permission_denied", "permission", permission, actor or "anonymous", after=detail)


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """对外(前端)暴露的用户视图,去除敏感字段,permissions 转为列表。"""
    if not user:
        return {}
    perms = user.get("permissions", set())
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "display_name": user.get("display_name"),
        "status": user.get("status"),
        "must_change_password": user.get("must_change_password", False),
        "roles": user.get("roles", []),
        "permissions": sorted(perms) if isinstance(perms, set) else list(perms),
        "last_login_at": user.get("last_login_at"),
    }
