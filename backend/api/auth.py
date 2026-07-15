"""
研判分析 - 认证与授权 API 蓝图
================================
- POST /api/auth/login           登录,签发会话 + CSRF cookie
- POST /api/auth/logout          注销,撤销会话
- GET  /api/auth/me              当前登录用户(含角色/权限)
- POST /api/auth/change-password 修改本人口令
- 用户管理(仅 system.manage):GET/POST /users, PUT /users/<id>, POST /users/<id>/password

同时对外提供:
- require_perm(permission) 装饰器:细粒度授权,默认拒绝
- verify_csrf():双提交 CSRF 校验(供 incident 蓝图复用)
- current_user():读取本次请求解析出的登录用户
"""
from functools import wraps

from flask import Blueprint, g, jsonify, request

from backend.services import auth_service
from backend.config import SECURE_COOKIE, COOKIE_SAMESITE


auth_bp = Blueprint("auth", __name__)

SESSION_COOKIE = "sid"
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
_COOKIE_MAX_AGE = auth_service.SESSION_ABSOLUTE_HOURS * 3600


# ---------- 请求级用户解析(应用级 before_request) ----------

@auth_bp.before_app_request
def load_current_user():
    """仅对 /api/ 请求解析身份:优先会话 cookie,其次服务令牌(自动化入库)。"""
    g.current_user = None
    if not request.path.startswith("/api/"):
        return
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        g.current_user = auth_service.resolve_session(token)
    if g.current_user is None:
        raw = _bearer_token()
        if raw:
            g.current_user = auth_service.resolve_api_token(raw)


def _bearer_token():
    """从 Authorization: Bearer <t> 或 X-API-Token: <t> 提取服务令牌明文。"""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return request.headers.get("X-API-Token", "").strip() or None


def current_user():
    return getattr(g, "current_user", None)


def is_service_request() -> bool:
    user = getattr(g, "current_user", None)
    return bool(user and user.get("is_service"))


# ---------- 授权工具 ----------

def require_perm(permission: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"success": False, "error": "未登录或会话已过期"}), 401
            if permission not in user.get("permissions", set()):
                auth_service.audit_denied(
                    user.get("username"), permission,
                    {"method": request.method, "path": request.path},
                )
                return jsonify({"success": False, "error": "权限不足,无法执行该操作"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def verify_csrf() -> bool:
    """双提交 cookie:请求头 X-CSRF-Token 必须与 csrf_token cookie 一致。"""
    header = request.headers.get(CSRF_HEADER, "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    return bool(cookie) and header == cookie


# ---------- cookie ----------

def _set_session_cookies(resp, token: str, csrf: str):
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, secure=SECURE_COOKIE,
                    samesite=COOKIE_SAMESITE, max_age=_COOKIE_MAX_AGE, path="/")
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=SECURE_COOKIE,
                    samesite=COOKIE_SAMESITE, max_age=_COOKIE_MAX_AGE, path="/")


def _clear_session_cookies(resp):
    resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.delete_cookie(CSRF_COOKIE, path="/")


# ---------- 蓝图级 CSRF 守卫(login 豁免:此时尚无会话) ----------

@auth_bp.before_request
def _auth_csrf_guard():
    # 服务令牌走 Authorization 头、不依赖 cookie，天然不受 CSRF 影响，予以豁免
    if request.method in ("POST", "PUT", "DELETE", "PATCH") and request.endpoint != "auth.login":
        if not is_service_request() and not verify_csrf():
            return jsonify({"success": False, "error": "CSRF 校验失败,请重新登录"}), 403


# ---------- 路由 ----------

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    ip = request.remote_addr or ""
    ua = request.headers.get("User-Agent", "")
    user, error = auth_service.verify_login(username, password, ip=ip, user_agent=ua)
    if error:
        return jsonify({"success": False, "error": error}), 401
    sess = auth_service.create_session(user["id"], ip=ip, user_agent=ua)
    resp = jsonify({"success": True, "data": auth_service.public_user(user)})
    _set_session_cookies(resp, sess["token"], sess["csrf"])
    return resp


@auth_bp.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get(SESSION_COOKIE)
    actor = (current_user() or {}).get("username")
    if token:
        auth_service.revoke_session(token, actor=actor)
    resp = jsonify({"success": True})
    _clear_session_cookies(resp)
    return resp


@auth_bp.route("/me", methods=["GET"])
def me():
    user = current_user()
    if not user:
        return jsonify({"success": False, "error": "未登录"}), 401
    return jsonify({"success": True, "data": auth_service.public_user(user)})


@auth_bp.route("/directory", methods=["GET"])
def directory():
    """指派选人用的精简用户目录。仅供需要指派的角色读取（分派/处置）。"""
    user = current_user()
    if not user:
        return jsonify({"success": False, "error": "未登录"}), 401
    perms = user.get("permissions", set())
    if not ({"alert.assign", "subtask.manage"} & set(perms)):
        return jsonify({"success": False, "error": "权限不足"}), 403
    role = request.args.get("role") or None
    return jsonify({"success": True, "data": {"users": auth_service.list_directory(role)}})


@auth_bp.route("/change-password", methods=["POST"])
def change_password():
    user = current_user()
    if not user:
        return jsonify({"success": False, "error": "未登录"}), 401
    data = request.get_json(silent=True) or {}
    ok, error = auth_service.change_password(
        user["id"], data.get("old_password", ""), data.get("new_password", "")
    )
    if error:
        return jsonify({"success": False, "error": error}), 400
    return jsonify({"success": True})


# ---------- 用户管理(仅管理员) ----------

@auth_bp.route("/users", methods=["GET"])
@require_perm("system.manage")
def list_users():
    return jsonify({"success": True, "data": {
        "users": auth_service.list_users(),
        "roles": auth_service.list_roles(),
    }})


@auth_bp.route("/users", methods=["POST"])
@require_perm("system.manage")
def create_user():
    data = request.get_json(silent=True) or {}
    try:
        user = auth_service.create_user(
            data.get("username", ""),
            data.get("password", ""),
            data.get("display_name", ""),
            data.get("roles", []),
            actor=current_user()["username"],
            must_change=bool(data.get("must_change", True)),
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    return jsonify({"success": True, "data": user})


@auth_bp.route("/users/<user_id>", methods=["PUT"])
@require_perm("system.manage")
def update_user(user_id):
    data = request.get_json(silent=True) or {}
    actor = current_user()["username"]
    try:
        if "roles" in data:
            auth_service.set_user_roles(user_id, data.get("roles", []), actor)
        if "status" in data:
            auth_service.set_user_status(user_id, data.get("status", ""), actor)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    result = auth_service.get_user(user_id)
    if not result:
        return jsonify({"success": False, "error": "用户不存在"}), 404
    return jsonify({"success": True, "data": auth_service.public_user(result)})


@auth_bp.route("/users/<user_id>/password", methods=["POST"])
@require_perm("system.manage")
def reset_user_password(user_id):
    data = request.get_json(silent=True) or {}
    try:
        auth_service.admin_reset_password(user_id, data.get("password", ""), current_user()["username"])
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    return jsonify({"success": True})


# ---------- 服务令牌（自动化入库，仅管理员） ----------

@auth_bp.route("/tokens", methods=["GET"])
@require_perm("system.manage")
def list_tokens():
    return jsonify({"success": True, "data": {
        "tokens": auth_service.list_api_tokens(),
        "allowed_scopes": sorted(auth_service.INGEST_TOKEN_SCOPES),
    }})


@auth_bp.route("/tokens", methods=["POST"])
@require_perm("system.manage")
def create_token():
    data = request.get_json(silent=True) or {}
    try:
        result = auth_service.create_api_token(
            data.get("name", ""),
            data.get("scopes", []),
            actor=current_user()["username"],
            expires_days=data.get("expires_days"),
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    # result 含一次性明文 token，仅本次返回
    return jsonify({"success": True, "data": result})


@auth_bp.route("/tokens/<token_id>", methods=["DELETE"])
@require_perm("system.manage")
def revoke_token(token_id):
    ok = auth_service.revoke_api_token(token_id, current_user()["username"])
    if not ok:
        return jsonify({"success": False, "error": "令牌不存在或已吊销"}), 404
    return jsonify({"success": True})


# ---------- 角色-权限矩阵（可配置，仅管理员） ----------

@auth_bp.route("/permissions", methods=["GET"])
@require_perm("system.manage")
def list_permissions():
    return jsonify({"success": True, "data": {
        "catalog": auth_service.list_permission_catalog(),
        "roles": auth_service.list_roles(),
        "matrix": auth_service.get_role_permissions(),
    }})


@auth_bp.route("/roles/<role_code>/permissions", methods=["PUT"])
@require_perm("system.manage")
def update_role_permissions(role_code):
    data = request.get_json(silent=True) or {}
    try:
        matrix = auth_service.set_role_permissions(
            role_code, data.get("permissions", []), current_user()["username"]
        )
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    return jsonify({"success": True, "data": {"matrix": matrix}})
