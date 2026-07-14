"""
研判分析 - API 蓝图
面向安全运营和应急响应工程师的告警录入、研判、关联和导出接口。
"""
import json

from flask import Blueprint, Response, jsonify, request, send_from_directory

from backend.services import incident_service
from backend.services import ocr_service


incident_bp = Blueprint("incident", __name__)
UPLOAD_BASE = incident_service.UPLOAD_BASE


def _actor() -> str:
    return request.headers.get("X-User") or request.args.get("actor") or "operator"


def _json_body() -> dict:
    return request.get_json(silent=True) or {}


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
    alerts = incident_service.list_alerts(filters)
    return jsonify({"success": True, "data": {"alerts": alerts, "count": len(alerts)}})


@incident_bp.route("/alerts/batch", methods=["POST"])
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
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>", methods=["PUT"])
def update_alert(alert_id):
    try:
        alert = incident_service.update_alert(alert_id, _json_body(), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>", methods=["DELETE"])
def delete_alert(alert_id):
    ok = incident_service.delete_alert(alert_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/attachments", methods=["GET"])
def list_alert_attachments(alert_id):
    if not incident_service.get_alert(alert_id):
        return jsonify({"success": False, "error": "告警不存在"}), 404
    items = incident_service.list_attachments(alert_id)
    return jsonify({"success": True, "data": {"attachments": items, "count": len(items)}})


@incident_bp.route("/alerts/<alert_id>/attachments", methods=["POST"])
def upload_alert_attachment(alert_id):
    if not incident_service.get_alert(alert_id):
        return jsonify({"success": False, "error": "告警不存在"}), 404
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
def delete_attachment(attachment_id):
    ok = incident_service.delete_attachment(attachment_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "附件不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/ocr/status", methods=["GET"])
def ocr_status():
    """OCR 能力探测：引擎是否就绪、用的哪个引擎、未就绪时的安装指引。"""
    return jsonify({"success": True, "data": ocr_service.engine_status()})


@incident_bp.route("/extract-fields", methods=["POST"])
def extract_fields():
    """从一段纯文本（如粘贴的告警内容）解析候选字段。纯规则，不依赖 OCR 引擎。"""
    text = _json_body().get("text", "")
    if not isinstance(text, str) or not text.strip():
        return jsonify({"success": False, "error": "文本为空"}), 400
    fields = ocr_service.parse_fields_from_text(text)
    return jsonify({"success": True, "data": {"fields": fields}})


@incident_bp.route("/alerts/<alert_id>/ocr", methods=["POST"])
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
    return jsonify({"success": True, "data": {"entities": alert.get("entities", [])}})


@incident_bp.route("/alerts/<alert_id>/entities", methods=["POST"])
def add_alert_entity(alert_id):
    try:
        entity = incident_service.add_entity(alert_id, _json_body(), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not entity:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": entity})


@incident_bp.route("/entities/<entity_id>", methods=["DELETE"])
def delete_entity(entity_id):
    ok = incident_service.delete_entity(entity_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "实体不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/notes", methods=["GET"])
def list_alert_notes(alert_id):
    alert = incident_service.get_alert(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": {"notes": alert.get("notes", [])}})


@incident_bp.route("/alerts/<alert_id>/notes", methods=["POST"])
def add_alert_note(alert_id):
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
def set_alert_status(alert_id):
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
def set_alert_conclusion(alert_id):
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
def add_alert_handler(alert_id):
    data = _json_body()
    try:
        alert = incident_service.assign_handler(alert_id, data.get("name", ""), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/handlers", methods=["DELETE"])
def remove_alert_handler(alert_id):
    data = _json_body()
    alert = incident_service.remove_handler(alert_id, data.get("name", ""), actor=_actor())
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/handlers", methods=["PUT"])
def set_alert_handlers(alert_id):
    data = _json_body()
    alert = incident_service.set_handlers(alert_id, data.get("names", []), actor=_actor())
    if not alert:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": alert})


@incident_bp.route("/alerts/<alert_id>/reject", methods=["POST"])
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
    if not incident_service.get_alert(alert_id):
        return jsonify({"success": False, "error": "告警不存在"}), 404
    items = incident_service.list_subtasks(alert_id)
    return jsonify({"success": True, "data": {"subtasks": items, "count": len(items)}})


@incident_bp.route("/alerts/<alert_id>/subtasks", methods=["POST"])
def add_alert_subtask(alert_id):
    try:
        item = incident_service.create_subtask(alert_id, _json_body(), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not item:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": item})


@incident_bp.route("/subtasks/<subtask_id>", methods=["PUT"])
def update_subtask(subtask_id):
    try:
        item = incident_service.update_subtask(subtask_id, _json_body(), actor=_actor())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    if not item:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    return jsonify({"success": True, "data": item})


@incident_bp.route("/subtasks/<subtask_id>", methods=["DELETE"])
def delete_subtask(subtask_id):
    ok = incident_service.delete_subtask(subtask_id, actor=_actor())
    if not ok:
        return jsonify({"success": False, "error": "子任务不存在"}), 404
    return jsonify({"success": True})


@incident_bp.route("/alerts/<alert_id>/related", methods=["GET"])
def related_alerts(alert_id):
    if not incident_service.get_alert(alert_id):
        return jsonify({"success": False, "error": "告警不存在"}), 404
    items = incident_service.get_related_alerts(alert_id)
    return jsonify({"success": True, "data": {"alerts": items, "count": len(items)}})


@incident_bp.route("/alerts/<alert_id>/correlation", methods=["GET"])
def alert_correlation(alert_id):
    limit = request.args.get("limit", 20, type=int)
    data = incident_service.get_alert_correlation(alert_id, limit=limit)
    if data is None:
        return jsonify({"success": False, "error": "告警不存在"}), 404
    return jsonify({"success": True, "data": data})


@incident_bp.route("/alerts/<alert_id>/export", methods=["GET"])
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
    return jsonify({"success": True, "data": incident_service.get_stats()})


@incident_bp.route("/operations/summary", methods=["GET"])
def get_operations_summary():
    days = request.args.get("days", 7, type=int)
    return jsonify({"success": True, "data": incident_service.get_operations_summary(days)})


@incident_bp.route("/operations/export", methods=["GET"])
def export_operations():
    days = request.args.get("days", 7, type=int)
    data = incident_service.export_operations_csv(days)
    return Response(
        data,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=incident-operations-{days}d.csv"},
    )


@incident_bp.route("/audit", methods=["GET"])
def get_audit():
    limit = request.args.get("limit", 100, type=int)
    return jsonify({"success": True, "data": {"items": incident_service.list_audit(limit)}})


# ===== 兼容旧接口 =====


@incident_bp.route("/upload_image", methods=["POST"])
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
def delete_image(image_id):
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
def export_session():
    return jsonify({"success": True, "data": incident_service.export_all()})


@incident_bp.route("/clear", methods=["POST"])
def clear_session():
    incident_service.clear_all()
    return jsonify({"success": True})
