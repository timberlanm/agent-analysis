"""
研判分析 - API 蓝图
面向安全运营和应急响应工程师的告警录入、研判、关联和导出接口。
"""
import json

from flask import Blueprint, Response, g, jsonify, request, send_from_directory

from backend.services import incident_service
from backend.services import ocr_service
from backend.services import auth_service
from backend.api.auth import require_perm, verify_csrf, current_user, is_service_request


incident_bp = Blueprint("incident", __name__)
UPLOAD_BASE = incident_service.UPLOAD_BASE


def _actor() -> str:
    """操作者 = 已登录用户名。会话缺失时回退到旧的请求头/参数（仅兜底）。"""
    user = getattr(g, "current_user", None)
    if user:
        return user["username"]
    return request.headers.get("X-User") or request.args.get("actor") or "operator"


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
    """指派类操作的对象级判定：非豁免角色仅可增删本人，且不得对已完成告警操作（防变相重开）。"""
    user = current_user()
    if auth_service.has_scope_bypass(user):
        return True, None
    username = user["username"]
    old = set(alert.get("handlers") or [])
    new = {str(n).strip() for n in (new_names or []) if str(n).strip()}
    if old.symmetric_difference(new) - {username}:
        return False, "仅可自领或退出本人处理，改派他人请联系研判主管"
    if alert.get("status") == "closed":
        return False, "已完成告警的重开请联系研判主管"
    return True, None


def _queue_vis() -> str:
    """当前用户的告警队列可见性：all / own+unassigned / own。"""
    return auth_service.queue_visibility(current_user())


def _is_unassigned(alert: dict) -> bool:
    return not (alert.get("handlers") or [])


def _read_restricted() -> bool:
    """当前用户的告警队列是否被收敛（非「看全部」即受限）。"""
    return _queue_vis() != "all"


def _read_ok(alert: dict) -> bool:
    """读可见性判定：看全部放行；否则须为经手/受指派者；上报人另可见待分配告警。"""
    vis = _queue_vis()
    if vis == "all":
        return True
    if _is_assigned(alert, current_user()["username"]):
        return True
    if vis == "own+unassigned" and _is_unassigned(alert):
        return True
    return False


def _read_forbidden():
    return jsonify({"success": False, "error": "无权查看该告警：仅限本人经手或受指派的告警"}), 403


@incident_bp.route("/alerts", methods=["GET"])
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
    # 队列读可见性：非「看全部」的角色只可见本人经手/受指派的告警；上报人另可见待分配
    vis = _queue_vis()
    if vis != "all":
        filters["restrict_to_actor"] = current_user()["username"]
        filters["include_unassigned"] = (vis == "own+unassigned")
    alerts = incident_service.list_alerts(filters)
    return jsonify({"success": True, "data": {"alerts": alerts, "count": len(alerts)}})


@incident_bp.route("/alerts/batch", methods=["POST"])
@require_perm("alert.edit")
def batch_alerts():
    data = _json_body()
    try:
        result = incident_service.batch_update_alerts(
            data.get("ids", []),
            data.get("action", ""),
            data.get("payload", {}),
            actor=_actor(),
        )
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


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
    try:
        alert = incident_service.create_alert(data, actor=_actor())
        return jsonify({"success": True, "data": alert})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@incident_bp.route("/alerts/<alert_id>", methods=["GET"])
def get_alert(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
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
        if parent and not _scope_ok(parent, "attachment.write"):
            return _scope_forbidden()
    ok = incident_service.delete_attachment(attachment_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "附件不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/ocr/status", methods=["GET"])
def ocr_status():
    """OCR 能力探测：引擎是否就绪、用的哪个引擎、未就绪时的安装指引。"""
    return jsonify({"success": True, "data": ocr_service.engine_status()})


@incident_bp.route("/extract-fields", methods=["POST"])
@require_perm("ocr.run")
def extract_fields():
    """从一段纯文本（如粘贴的告警内容）解析候选字段。纯规则，不依赖 OCR 引擎。"""
    text = _json_body().get("text", "")
    if not isinstance(text, str) or not text.strip():
        return jsonify({"success": False, "error": "文本为空"}), 400
    fields = ocr_service.parse_fields_from_text(text)
    return jsonify({"success": True, "data": {"fields": fields}})


@incident_bp.route("/alerts/<alert_id>/ocr", methods=["POST"])
@require_perm("ocr.run")
def ocr_alert(alert_id):
    """对该告警的图片附件做 OCR，返回候选字段供研判员核对（不写库）。"""
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    try:
        result = ocr_service.extract_from_alert(alert_id)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    return jsonify({"success": True, "data": result})


@incident_bp.route("/alerts/<alert_id>/entities", methods=["GET"])
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
        if parent and not _scope_ok(parent, "alert.entity"):
            return _scope_forbidden()
    ok = incident_service.delete_entity(entity_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "实体不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/notes", methods=["GET"])
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
            data.get("author") or _actor(),
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
    try:
        item = incident_service.create_subtask(alert_id, _json_body(), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not item:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": item})


@incident_bp.route("/subtasks/<subtask_id>", methods=["PUT"])
@require_perm("subtask.manage")
def update_subtask(subtask_id):
    subtask = incident_service.get_subtask(subtask_id)
    if not subtask:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    parent = incident_service.get_alert(subtask.get("alert_id"))
    if parent and not _scope_ok(parent, "subtask.manage"):
        return _scope_forbidden()
    try:
        item = incident_service.update_subtask(subtask_id, _json_body(), actor=_actor())
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
    if parent and not _scope_ok(parent, "subtask.manage"):
        return _scope_forbidden()
    ok = incident_service.delete_subtask(subtask_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/related", methods=["GET"])
def related_alerts(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    items = incident_service.get_related_alerts(alert_id)
    return jsonify({"success": True, "data": {"alerts": items, "count": len(items)}})


@incident_bp.route("/alerts/<alert_id>/correlation", methods=["GET"])
def alert_correlation(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    if not _read_ok(alert):
        return _read_forbidden()
    limit = request.args.get("limit", 20, type=int)
    data = incident_service.get_alert_correlation(alert_id, limit=limit)
    if data is None:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": data})


@incident_bp.route("/alerts/<alert_id>/export", methods=["GET"])
@require_perm("export")
def export_alert(alert_id):
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
    return jsonify({"success": True, "data": data})


@incident_bp.route("/stats", methods=["GET"])
def get_stats():
    vis = _queue_vis()
    restrict = None if vis == "all" else current_user()["username"]
    include_unassigned = (vis == "own+unassigned")
    return jsonify({"success": True, "data": incident_service.get_stats(restrict, include_unassigned)})


@incident_bp.route("/operations/summary", methods=["GET"])
def get_operations_summary():
    days = request.args.get("days", 7, type=int)
    return jsonify({"success": True, "data": incident_service.get_operations_summary(days)})


@incident_bp.route("/operations/export", methods=["GET"])
@require_perm("export")
def export_operations():
    days = request.args.get("days", 7, type=int)
    data = incident_service.export_operations_csv(days)
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
    info, err = incident_service.save_image(file_storage)
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
        meta, err = incident_service.save_alert_from_file(file_storage)
        if err:
            return jsonify({"success": False, "error": err}), 400
        return jsonify({"success": True, "data": meta})

    if "application/json" in (request.content_type or ""):
        raw = request.get_json(silent=True)
        if raw is None:
            return jsonify({"success": False, "error": "JSON 解析失败"}), 400
        if not isinstance(raw, dict):
            return jsonify({"success": False, "error": "告警 JSON 必须是对象"}), 400
        meta = incident_service.save_alert_from_json(raw)
        return jsonify({"success": True, "data": meta})

    return jsonify({"success": False, "error": "请通过文件上传或 JSON 提交告警"}), 400


@incident_bp.route("/images", methods=["GET"])
def list_images():
    images = incident_service.list_images()
    return jsonify({"success": True, "data": {"images": images, "count": len(images)}})


@incident_bp.route("/images/<image_id>", methods=["DELETE"])
@require_perm("attachment.write")
def delete_image(image_id):
    item = incident_service.get_attachment(image_id)
    if item and item.get("alert_id"):
        parent = incident_service.get_alert(item["alert_id"])
        if parent and not _scope_ok(parent, "attachment.write"):
            return _scope_forbidden()
    ok = incident_service.delete_image(image_id)
    if not ok:
        return jsonify({"success": False, "error": "图片不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/files/<path:filepath>", methods=["GET"])
def serve_file(filepath):
    full = incident_service.resolve_file_path(filepath)
    if not full or not full.is_file():
        return jsonify({"success": False, "error": "文件不存在"}), 404
    # 文本类日志以 text/plain 内联返回，便于浏览器直接查看（而非下载）
    mimetype = None
    if full.suffix.lower() in {".log", ".txt"}:
        mimetype = "text/plain"  # Flask 会自动补 charset=utf-8
    return send_from_directory(str(full.parent), full.name, mimetype=mimetype)


@incident_bp.route("/export", methods=["GET"])
@require_perm("export")
def export_session():
    return jsonify({"success": True, "data": incident_service.export_all()})


@incident_bp.route("/clear", methods=["POST"])
@require_perm("data.clear")
def clear_session():
    incident_service.clear_all()
    return jsonify({"success": True})
