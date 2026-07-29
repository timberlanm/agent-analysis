"""
研判分析 - API 蓝图
面向安全运营和应急响应工程师的告警录入、研判、关联和导出接口。
"""
import json

from flask import Blueprint, Response, g, jsonify, request, send_from_directory

from backend.services import incident_service
from backend.services import auth_service
from backend.api.auth import require_perm, verify_csrf, current_user, is_service_request


incident_bp = Blueprint("incident", __name__)
UPLOAD_BASE = incident_service.UPLOAD_BASE


def _actor() -> str:
    """操作者 = 已登录用户名。

    所有 /api/incident/* 接口均由 _require_login 强制登录，正常请求中
    g.current_user 必然存在。若因路由调整等意外导致此处拿不到登录用户，
    绝不可信任客户端头/参数（历史遗留的 X-User / actor 曾是身份伪造后门），
    返回固定常量以安全降级，避免污染归属与审计。
    """
    user = getattr(g, "current_user", None)
    if user:
        return user["username"]
    return "anonymous"


@incident_bp.before_request
def _require_login():
    """所有 /api/incident/* 接口一律要求登录；写操作再叠加 CSRF 校验。
    细粒度权限由各接口的 @require_perm 负责。"""
    if request.method == "OPTIONS":
        return None
    if getattr(g, "current_user", None) is None:
        return jsonify({"success": False, "error": "未登录或会话已过期"}), 401
    # 服务令牌(Authorization 头)不依赖 cookie，天然免疫 CSRF，予以豁免
    if request.method in ("POST", "PUT", "DELETE", "PATCH") and not is_service_request() and not verify_csrf():
        return jsonify({"success": False, "error": "CSRF 校验失败,请重新登录"}), 403


def _json_body() -> dict:
    return request.get_json(silent=True) or {}


# ===== 对象级授权（Phase 1：越权收敛） =====
# 非豁免角色（研判员/处置人）只能操作本人经手/受指派的告警；主管、管理员不受限。

def _scope_forbidden(msg: str = "无权操作该告警：仅限本人经手或受指派的告警"):
    user = current_user() or {}
    auth_service.audit_denied(
        user.get("username"), "object.scope",
        {"method": request.method, "path": request.path, "ip": request.remote_addr or ""},
    )
    return jsonify({"success": False, "error": msg}), 403


def _is_handler(alert: dict, username: str) -> bool:
    if not alert or not username:
        return False
    # owner / 处理人 / 创建者 均视为本人经手（创建者可续办自己录入的告警，无需再自领）
    if username in {alert.get("owner") or "", alert.get("created_by") or ""}:
        return True
    return username in (alert.get("handlers") or [])


def _is_assigned(alert: dict, username: str) -> bool:
    if _is_handler(alert, username):
        return True
    for subtask in (alert.get("subtasks") or []):
        if (subtask.get("assignee") or "") == username:
            return True
    return False


def _scope_ok(alert: dict, permission: str) -> bool:
    """按当前登录用户对该告警的归属关系判断对象级授权。"""
    user = current_user()
    scope = auth_service.effective_scope(user, permission)
    if scope is None:
        return True
    username = user["username"]
    if scope == "handler":
        return _is_handler(alert, username)
    if scope == "assigned":
        return _is_assigned(alert, username)
    return True  # 'self'（指派自领）由 handler 端点单独处理


def _handler_change_allowed(alert: dict, new_names):
    """指派类操作的对象级判定。

    管理员可全局指派；其他持有指派权限的角色可处理尚未分派或本人经手的告警，
    但不能越权改动已由他人接手的告警，也不能通过指派变相重开已完成告警。
    """
    user = current_user()
    new = {str(n).strip() for n in (new_names or []) if str(n).strip()}
    inactive = sorted(n for n in new if not auth_service.is_active_username(n))
    if inactive:
        return False, "处理人账号不存在或已停用：" + "、".join(inactive)
    if auth_service.has_scope_bypass(user):
        return True, None
    username = user["username"]
    old = set(alert.get("handlers") or [])
    if alert.get("status") == "closed":
        return False, "已完成告警的重开请联系研判主管"
    scope = auth_service.effective_scope(user, "alert.assign")
    if scope == "self":
        if old.symmetric_difference(new) - {username}:
            return False, "仅可自领或退出本人处理，改派他人请联系研判主管"
        return True, None
    if old and not _is_handler(alert, username):
        return False, "无权改派该告警：仅限当前处理人或告警上报人操作"
    return True, None


def _queue_vis() -> str:
    """当前用户的告警队列可见性：all / own+unassigned / own。"""
    return auth_service.queue_visibility(current_user())

def _visibility_args():
    vis = _queue_vis()
    return (None if vis == "all" else current_user()["username"],
            vis == "own+unassigned")


def _is_unassigned(alert: dict) -> bool:
    return not (alert.get("handlers") or [])


def _read_restricted() -> bool:
    """当前用户的告警队列是否被收敛（非「看全部」即受限）。"""
    return _queue_vis() != "all"


def _read_ok(alert: dict, audit_denial: bool = True) -> bool:
    """读可见性判定：管理员全局可见；研判人员另可见待分配告警；其他角色仅限归属对象。"""
    vis = _queue_vis()
    if "alert.view" not in current_user().get("permissions", set()):
        return False
    if vis == "all":
        return True
    if _is_assigned(alert, current_user()["username"]):
        return True
    if vis == "own+unassigned" and _is_unassigned(alert):
        return True
    if audit_denial:
        auth_service.audit_denied(
            current_user().get("username"), "alert.view.scope",
            {"method": request.method, "path": request.path, "ip": request.remote_addr or ""},
        )
    return False


def _read_forbidden():
    return jsonify({"success": False, "error": "无权查看该告警：仅限本人经手或受指派的告警"}), 403


@incident_bp.route("/alerts", methods=["GET"])
@require_perm("alert.view")
def list_alerts():
    filters = {
        "keyword": request.args.get("keyword", ""),
        "source_category": request.args.get("source_category", ""),
        "status": request.args.get("status", ""),
        "severity": request.args.get("severity", ""),
        "conclusion": request.args.get("conclusion", ""),
        "owner": request.args.get("owner", ""),
        "reporter": request.args.get("reporter", ""),
        "source_system": request.args.get("source_system", ""),
        "queue": request.args.get("queue", "all"),
        "current_user": request.args.get("current_user", _actor()),
        "limit": request.args.get("limit", 200),
        "offset": request.args.get("offset", 0),
    }
    # 队列读可见性：研判人员可认领待分配告警；其他非管理员角色仅可见本人经手/受指派告警。
    vis = _queue_vis()
    if vis != "all":
        filters["restrict_to_actor"] = current_user()["username"]
        filters["include_unassigned"] = (vis == "own+unassigned")
    alerts = incident_service.list_alerts(filters)
    return jsonify({"success": True, "data": {"alerts": alerts, "count": len(alerts)}})


@incident_bp.route("/alerts/batch", methods=["POST"])
@require_perm("alert.view")
def batch_alerts():
    data = _json_body()
    action = str(data.get("action") or "").strip()
    permission_map = {
        "assign": "alert.assign",
        "status": "alert.status",
        "severity": "alert.edit",
        "note": "alert.note",
    }
    permission = permission_map.get(action)
    if not permission:
        return jsonify({"success": False, "error": "不支持的批量操作"}), 400
    user = current_user()
    if permission not in user.get("permissions", set()):
        auth_service.audit_denied(
            user.get("username"), permission,
            {"method": request.method, "path": request.path, "ip": request.remote_addr or ""},
        )
        return jsonify({"success": False, "error": "权限不足，无法执行该批量操作"}), 403
    raw_ids = data.get("ids", [])
    if not isinstance(raw_ids, list):
        return jsonify({"success": False, "error": "告警 ID 列表格式无效"}), 400
    alert_ids = list(dict.fromkeys(str(item).strip() for item in raw_ids if str(item).strip()))[:200]
    if not alert_ids:
        return jsonify({"success": False, "error": "请选择需要批量操作的告警"}), 400
    payload = data.get("payload", {}) if isinstance(data.get("payload", {}), dict) else {}
    allowed = []
    denied = []
    for alert_id in alert_ids:
        existing = incident_service.get_alert(alert_id)
        if not existing:
            denied.append({"id": alert_id, "error": "告警不存在"})
            continue
        if action == "assign":
            owner = str(payload.get("owner") or "").strip()
            ok, err = _handler_change_allowed(existing, [owner] if owner else [])
        else:
            ok = _scope_ok(existing, permission)
            err = None if ok else "无权操作该告警"
        if not ok:
            auth_service.audit_denied(
                user.get("username"), permission,
                {"method": request.method, "path": request.path, "target_id": alert_id},
            )
            denied.append({"id": alert_id, "error": err})
            continue
        allowed.append(alert_id)
    if not allowed:
        return jsonify({"success": True, "data": {"requested": len(alert_ids), "updated": 0, "errors": denied}})
    try:
        result = incident_service.batch_update_alerts(allowed, action, payload, actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    result["requested"] = len(alert_ids)
    result["errors"] = denied + list(result.get("errors") or [])
    return jsonify({"success": True, "data": result})


@incident_bp.route("/templates", methods=["GET"])
def get_alert_templates():
    return jsonify({
        "success": True,
        "data": {
            "templates": incident_service.ALERT_SOURCE_TEMPLATES
        }
    })


@incident_bp.route("/alerts", methods=["POST"])
@require_perm("alert.create")
def create_alert():
    data = _json_body()
    protected = {"status", "conclusion", "close_reason", "owner", "handlers", "created_by", "updated_by", "reporter", "attachments"}
    for field in protected:
        data.pop(field, None)
    try:
        alert = incident_service.create_alert(data, actor=_actor())
        return jsonify({"success": True, "data": alert})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@incident_bp.route("/alerts/<alert_id>", methods=["GET"])
@require_perm("alert.view")
def get_alert(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    restrict, include_unassigned = _visibility_args()
    correlation = incident_service.get_alert_correlation(
        alert_id, limit=8, restrict_to_actor=restrict, include_unassigned=include_unassigned)
    alert["correlation"] = correlation or {"summary": {}, "entity_profiles": [], "related_alerts": []}
    alert["related"] = alert["correlation"]["related_alerts"]
    if "audit.view" in current_user().get("permissions", set()):
        alert["audit"] = incident_service.list_audit(100, {"target_id": alert_id})
    return jsonify({"success": True, "data": alert})

@incident_bp.route("/alerts/<alert_id>", methods=["PUT"])
@require_perm("alert.edit")
def update_alert(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.edit"):
        return _scope_forbidden()
    try:
        alert = incident_service.update_alert(alert_id, _json_body(), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>", methods=["DELETE"])
@require_perm("alert.delete")
def delete_alert(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.delete"):
        return _scope_forbidden()
    ok = incident_service.delete_alert(alert_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/attachments", methods=["GET"])
@require_perm("alert.view")
def list_alert_attachments(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    items = incident_service.list_attachments(alert_id)
    return jsonify({"success": True, "data": {"attachments": items, "count": len(items)}})


@incident_bp.route("/alerts/<alert_id>/attachments", methods=["POST"])
@require_perm("attachment.write")
def upload_alert_attachment(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "attachment.write"):
        return _scope_forbidden()
    files = request.files.getlist("file") or request.files.getlist("attachment") or request.files.getlist("image")
    if not files:
        return jsonify({"success": False, "error": "未找到上传文件"}), 400
    description = request.form.get("description", "")
    uploaded = []
    for file_storage in files:
        info, err = incident_service.save_attachment(file_storage, alert_id, description, actor=_actor())
        if err:
            return jsonify({"success": False, "error": err}), 400
        uploaded.append(info)
    return jsonify({"success": True, "data": {"attachments": uploaded}})


@incident_bp.route("/attachments/<attachment_id>", methods=["DELETE"])
@require_perm("attachment.write")
def delete_attachment(attachment_id):
    item = incident_service.get_attachment(attachment_id)
    if not item:
        return jsonify({"success": False, "error": "附件不存在"}), 404
    parent_id = item.get("alert_id")
    if parent_id:
        parent = incident_service.get_alert(parent_id)
        if not parent or not _scope_ok(parent, "attachment.write"):
            return _scope_forbidden()
    elif not (auth_service.has_scope_bypass(current_user()) or item.get("uploaded_by") == _actor()):
        return _scope_forbidden("无权删除其他人上传的未关联附件")
    ok = incident_service.delete_attachment(attachment_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "附件不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/entities", methods=["GET"])
@require_perm("alert.view")
def list_alert_entities(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    return jsonify({"success": True, "data": {"entities": alert.get("entities", [])}})


@incident_bp.route("/alerts/<alert_id>/entities", methods=["POST"])
@require_perm("alert.entity")
def add_alert_entity(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.entity"):
        return _scope_forbidden()
    try:
        entity = incident_service.add_entity(alert_id, _json_body(), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not entity:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": entity})


@incident_bp.route("/entities/<entity_id>", methods=["DELETE"])
@require_perm("alert.entity")
def delete_entity(entity_id):
    parent_id = incident_service.get_entity_alert_id(entity_id)
    if parent_id:
        parent = incident_service.get_alert(parent_id)
        if not parent or not _scope_ok(parent, "alert.entity"):
            return _scope_forbidden()
    ok = incident_service.delete_entity(entity_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "实体不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/notes", methods=["GET"])
@require_perm("alert.view")
def list_alert_notes(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    return jsonify({"success": True, "data": {"notes": alert.get("notes", [])}})


@incident_bp.route("/alerts/<alert_id>/notes", methods=["POST"])
@require_perm("alert.note")
def add_alert_note(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.note"):
        return _scope_forbidden()
    data = _json_body()
    try:
        note = incident_service.add_note(
            alert_id,
            data.get("content", ""),
            data.get("note_type", "manual"),
            _actor(),
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not note:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": note})


@incident_bp.route("/alerts/<alert_id>/status", methods=["POST"])
@require_perm("alert.status")
def set_alert_status(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.status"):
        return _scope_forbidden()
    data = _json_body()
    if data.get("status") == "closed":
        permissions = current_user().get("permissions", set())
        if str(data.get("conclusion") or "").strip() and "alert.conclude" not in permissions:
            return _scope_forbidden("关闭时写入研判结论需要“研判定性”权限")
        if (str(data.get("key_evidence") or "").strip() or str(data.get("handling_suggestion") or "").strip()) and "alert.edit" not in permissions:
            return _scope_forbidden("关闭时写入研判信息需要“编辑告警”权限")
    try:
        close_payload = {
            "close_reason": data.get("close_reason") or data.get("reason", ""),
            "conclusion": data.get("conclusion", ""),
            "key_evidence": data.get("key_evidence", ""),
            "handling_suggestion": data.get("handling_suggestion", ""),
        }
        reason = close_payload if data.get("status") == "closed" else data.get("reason", "")
        alert = incident_service.set_status(alert_id, data.get("status", ""), _actor(), reason)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/conclusion", methods=["POST"])
@require_perm("alert.conclude")
def set_alert_conclusion(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.conclude"):
        return _scope_forbidden()
    data = _json_body()
    if (data.get("conclusion") in incident_service.AUTO_RESPONDING_CONCLUSIONS
            and existing.get("status") not in ("closed", "responding")
            and "alert.status" not in current_user().get("permissions", set())):
        return _scope_forbidden("该结论会触发状态流转，需要“状态流转”权限")
    try:
        alert = incident_service.set_conclusion(
            alert_id,
            data.get("conclusion", ""),
            _actor(),
            data.get("content", ""),
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/handlers", methods=["POST"])
@require_perm("alert.assign")
def add_alert_handler(alert_id):
    data = _json_body()
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    new_handlers = list(existing.get("handlers") or []) + [data.get("name", "")]
    ok, err = _handler_change_allowed(existing, new_handlers)
    if not ok:
        return _scope_forbidden(err)
    try:
        alert = incident_service.assign_handler(alert_id, data.get("name", ""), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/handlers", methods=["DELETE"])
@require_perm("alert.assign")
def remove_alert_handler(alert_id):
    data = _json_body()
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    remaining = [h for h in (existing.get("handlers") or []) if h != data.get("name", "")]
    ok, err = _handler_change_allowed(existing, remaining)
    if not ok:
        return _scope_forbidden(err)
    alert = incident_service.remove_handler(alert_id, data.get("name", ""), actor=_actor())
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/handlers", methods=["PUT"])
@require_perm("alert.assign")
def set_alert_handlers(alert_id):
    data = _json_body()
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    ok, err = _handler_change_allowed(existing, data.get("names", []))
    if not ok:
        return _scope_forbidden(err)
    alert = incident_service.set_handlers(alert_id, data.get("names", []), actor=_actor())
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/reject", methods=["POST"])
@require_perm("alert.reject")
def reject_alert(alert_id):
    data = _json_body()
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.reject"):
        return _scope_forbidden()
    try:
        alert = incident_service.reject_alert(alert_id, data.get("reason", ""), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/reopen", methods=["POST"])
@require_perm("alert.reopen")
def reopen_alert(alert_id):
    data = _json_body()
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "alert.reopen"):
        return _scope_forbidden()
    try:
        alert = incident_service.reopen_alert(
            alert_id,
            data.get("conclusion", ""),
            _actor(),
            data.get("reason", ""),
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/subtasks", methods=["GET"])
@require_perm("alert.view")
def list_alert_subtasks(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    items = incident_service.list_subtasks(alert_id)
    return jsonify({"success": True, "data": {"subtasks": items, "count": len(items)}})


@incident_bp.route("/alerts/<alert_id>/subtasks", methods=["POST"])
@require_perm("subtask.manage")
def add_alert_subtask(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _scope_ok(existing, "subtask.manage"):
        return _scope_forbidden()
    data = _json_body()
    assignee = str(data.get("assignee") or "").strip()
    if assignee and not auth_service.is_active_username(assignee):
        return jsonify({"success": False, "error": "子任务负责人账号不存在或已停用"}), 400
    try:
        item = incident_service.create_subtask(alert_id, data, actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not item:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": item})


@incident_bp.route("/subtasks/<subtask_id>", methods=["PUT"])
def update_subtask(subtask_id):
    subtask = incident_service.get_subtask(subtask_id)
    if not subtask:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    parent = incident_service.get_alert(subtask.get("alert_id"))
    data = _json_body()
    permissions = current_user().get("permissions", set())
    actor = _actor()
    # 执行人身份优先：当调用者正是该子任务的指派执行人时，无论其是否同时持有
    # subtask.manage（双角色场景），都强制按「执行人」语义处理——只能更新 status，
    # 避免因角色叠加而升级到全字段编辑（H1 垂直越权）。
    is_assignee = subtask.get("assignee") == actor
    if is_assignee and "subtask.execute" in permissions:
        forbidden = set(data) - {"status"}
        if forbidden:
            return jsonify({"success": False, "error": "执行人仅可更新子任务状态"}), 403
        if "status" not in data:
            return jsonify({"success": False, "error": "请提供子任务状态"}), 400
    elif "subtask.manage" in permissions:
        if not parent or not _scope_ok(parent, "subtask.manage"):
            return _scope_forbidden()
        assignee = str(data.get("assignee") or "").strip()
        if assignee and not auth_service.is_active_username(assignee):
            return jsonify({"success": False, "error": "子任务负责人账号不存在或已停用"}), 400
    elif "subtask.execute" in permissions:
        # 持有 execute 但不是该子任务执行人 -> 拒绝
        return _scope_forbidden("仅可更新本人负责的子任务")
    else:
        auth_service.audit_denied(actor, "subtask.execute", {"method": request.method, "path": request.path})
        return jsonify({"success": False, "error": "权限不足，无法更新子任务"}), 403
    try:
        item = incident_service.update_subtask(subtask_id, data, actor=actor)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not item:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    return jsonify({"success": True, "data": item})

@incident_bp.route("/subtasks/<subtask_id>", methods=["DELETE"])
@require_perm("subtask.manage")
def delete_subtask(subtask_id):
    subtask = incident_service.get_subtask(subtask_id)
    if not subtask:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    parent = incident_service.get_alert(subtask.get("alert_id"))
    if not parent or not _scope_ok(parent, "subtask.manage"):
        return _scope_forbidden()
    ok = incident_service.delete_subtask(subtask_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/related", methods=["GET"])
@require_perm("alert.view")
def related_alerts(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    restrict, include_unassigned = _visibility_args()
    items = incident_service.get_related_alerts(
        alert_id, restrict_to_actor=restrict, include_unassigned=include_unassigned)
    return jsonify({"success": True, "data": {"alerts": items, "count": len(items)}})


@incident_bp.route("/alerts/<alert_id>/correlation", methods=["GET"])
@require_perm("alert.view")
def alert_correlation(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    limit = request.args.get("limit", 20, type=int)
    restrict, include_unassigned = _visibility_args()
    data = incident_service.get_alert_correlation(
        alert_id, limit=limit, restrict_to_actor=restrict, include_unassigned=include_unassigned)
    if data is None:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": data})


@incident_bp.route("/alerts/<alert_id>/export", methods=["GET"])
@require_perm("alert.view")
@require_perm("export")
def export_alert(alert_id):
    existing = incident_service.get_alert(alert_id)
    if not existing:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(existing):
        return _read_forbidden()
    fmt = request.args.get("format", "json")
    data = incident_service.export_alert(alert_id, fmt)
    if data is None:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if fmt == "markdown":
        return Response(
            data,
            mimetype="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=alert-{alert_id}.md"},
        )
    restrict, include_unassigned = _visibility_args()
    correlation = incident_service.get_alert_correlation(
        alert_id, limit=8, restrict_to_actor=restrict, include_unassigned=include_unassigned)
    data["correlation"] = correlation or {"summary": {}, "entity_profiles": [], "related_alerts": []}
    data["related"] = data["correlation"]["related_alerts"]
    return jsonify({"success": True, "data": data})


@incident_bp.route("/stats", methods=["GET"])
@require_perm("alert.view")
def get_stats():
    restrict, include_unassigned = _visibility_args()
    return jsonify({"success": True, "data": incident_service.get_stats(restrict, include_unassigned)})


@incident_bp.route("/operations/summary", methods=["GET"])
@require_perm("alert.view")
def get_operations_summary():
    days = request.args.get("days", 7, type=int)
    restrict, include_unassigned = _visibility_args()
    data = incident_service.get_operations_summary(days, restrict, include_unassigned)
    return jsonify({"success": True, "data": data})


@incident_bp.route("/operations/export", methods=["GET"])
@require_perm("alert.view")
@require_perm("export")
def export_operations():
    days = request.args.get("days", 7, type=int)
    restrict, include_unassigned = _visibility_args()
    data = incident_service.export_operations_csv(days, restrict, include_unassigned)
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=incident-operations-{days}d.csv"},
    )


def _audit_filters():
    return {
        "actor": request.args.get("actor", ""),
        "action": request.args.get("action", ""),
        "target_type": request.args.get("target_type", ""),
        "target_id": request.args.get("target_id", ""),
        "keyword": request.args.get("keyword", ""),
        "start": request.args.get("start", ""),
        "end": request.args.get("end", ""),
    }


@incident_bp.route("/audit", methods=["GET"])
@require_perm("audit.view")
def get_audit():
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    items = incident_service.list_audit(limit, filters=_audit_filters(), offset=offset)
    return jsonify({"success": True, "data": {"items": items}})


@incident_bp.route("/audit/verify", methods=["GET"])
@require_perm("audit.view")
def verify_audit():
    return jsonify({"success": True, "data": incident_service.verify_audit_chain()})


@incident_bp.route("/audit/export", methods=["GET"])
@require_perm("audit.view")
def export_audit():
    data = incident_service.export_audit_csv(filters=_audit_filters())
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=audit-log.csv"},
    )


# ===== 兼容旧接口 =====


@incident_bp.route("/upload_image", methods=["POST"])
@require_perm("attachment.write")
def upload_image():
    if "image" not in request.files:
        return jsonify({"success": False, "error": "未找到 image 字段"}), 400
    file_storage = request.files["image"]
    if file_storage.filename == "":
        return jsonify({"success": False, "error": "未选择文件"}), 400
    if not auth_service.has_scope_bypass(current_user()):
        return _scope_forbidden("旧版独立图片上传仅限管理员使用，请从具体告警上传附件")
    info, err = incident_service.save_image(file_storage, actor=_actor())
    if err:
        return jsonify({"success": False, "error": err}), 400
    return jsonify({"success": True, "data": info})


@incident_bp.route("/upload_alert", methods=["POST"])
@require_perm("alert.create")
def upload_alert():
    if "alert" in request.files:
        file_storage = request.files["alert"]
        if file_storage.filename == "":
            return jsonify({"success": False, "error": "未选择文件"}), 400
        meta, err = incident_service.save_alert_from_file(file_storage, actor=_actor())
        if err:
            return jsonify({"success": False, "error": err}), 400
        return jsonify({"success": True, "data": meta})

    if "application/json" in (request.content_type or ""):
        raw = request.get_json(silent=True)
        if raw is None:
            return jsonify({"success": False, "error": "JSON 解析失败"}), 400
        if not isinstance(raw, dict):
            return jsonify({"success": False, "error": "告警 JSON 必须是对象"}), 400
        meta = incident_service.save_alert_from_json(raw, actor=_actor())
        return jsonify({"success": True, "data": meta})

    return jsonify({"success": False, "error": "请通过文件上传或 JSON 提交告警"}), 400


@incident_bp.route("/images", methods=["GET"])
@require_perm("alert.view")
def list_images():
    images = []
    username = current_user()["username"]
    for item in incident_service.list_images():
        parent_id = item.get("alert_id")
        if parent_id:
            parent = incident_service.get_alert(parent_id)
            if parent and _read_ok(parent, audit_denial=False):
                images.append(item)
        elif auth_service.has_scope_bypass(current_user()) or item.get("uploaded_by") == username:
            images.append(item)
    return jsonify({"success": True, "data": {"images": images, "count": len(images)}})


@incident_bp.route("/images/<image_id>", methods=["DELETE"])
@require_perm("attachment.write")
def delete_image(image_id):
    item = incident_service.get_attachment(image_id)
    if not item:
        return jsonify({"success": False, "error": "图片不存在"}), 404
    if item.get("alert_id"):
        parent = incident_service.get_alert(item["alert_id"])
        if not parent or not _scope_ok(parent, "attachment.write"):
            return _scope_forbidden()
    elif not (auth_service.has_scope_bypass(current_user())
              or item.get("uploaded_by") == current_user()["username"]):
        return _scope_forbidden()
    ok = incident_service.delete_image(image_id, actor=_actor())
    return jsonify({"success": bool(ok)})


@incident_bp.route("/files/<path:filepath>", methods=["GET"])
@require_perm("alert.view")
def serve_file(filepath):
    item = incident_service.get_attachment_by_path(filepath)
    if not item:
        return jsonify({"success": False, "error": "文件不存在"}), 404
    if item.get("alert_id"):
        parent = incident_service.get_alert(item["alert_id"])
        if not parent or not _read_ok(parent):
            return _read_forbidden()
    elif not (auth_service.has_scope_bypass(current_user())
              or item.get("uploaded_by") == current_user()["username"]):
        return _read_forbidden()
    full = incident_service.resolve_file_path(item["rel_path"])
    if not full or not full.is_file():
        return jsonify({"success": False, "error": "文件不存在"}), 404
    # 文本类日志以 text/plain 内联返回，便于浏览器直接查看（而非下载）
    mimetype = None
    if full.suffix.lower() in {".log", ".txt"}:
        mimetype = "text/plain"  # Flask 会自动补 charset=utf-8
    return send_from_directory(str(full.parent), full.name, mimetype=mimetype)


@incident_bp.route("/export", methods=["GET"])
@require_perm("alert.view")
@require_perm("export")
def export_session():
    restrict, include_unassigned = _visibility_args()
    data = incident_service.export_all(restrict, include_unassigned)
    return jsonify({"success": True, "data": data})


@incident_bp.route("/clear", methods=["POST"])
@require_perm("data.clear")
def clear_session():
    incident_service.clear_all(actor=_actor())
    return jsonify({"success": True})
