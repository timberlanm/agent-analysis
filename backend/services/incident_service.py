"""
研判分析 - 服务层
多源安全告警录入、附件管理、实体抽取、研判记录、关联查询和审计。
"""
import json
import os
import re
import sqlite3
import uuid
from collections import Counter
from datetime import datetime, timezone
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
UPLOAD_BASE = str(BASE_DIR / "uploads" / "incident")
DB_PATH = DATA_DIR / "analysis_store.db"

ALLOWED_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
LOG_EXTENSIONS = {".json", ".txt", ".log", ".csv", ".out"}
COMPRESSED_LOG_EXTENSIONS = {".gz", ".bz2", ".xz", ".zip"}
PACKET_EXTENSIONS = {".pcap", ".pcapng"}
ALLOWED_ATTACHMENT_EXT = (
    ALLOWED_IMAGE_EXT | LOG_EXTENSIONS | COMPRESSED_LOG_EXTENSIONS | PACKET_EXTENSIONS
)
MAX_IMAGE_SIZE = 10 * 1024 * 1024
MAX_LOG_SIZE = 200 * 1024 * 1024
MAX_FORENSIC_FILE_SIZE = 500 * 1024 * 1024
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024
FILE_SAMPLE_SIZE = 64 * 1024
COPY_CHUNK_SIZE = 1024 * 1024

PCAP_MAGIC_HEADERS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
PCAPNG_MAGIC_HEADER = b"\x0a\x0d\x0d\x0a"
COMPRESSED_MAGIC_HEADERS = {
    ".gz": (b"\x1f\x8b",),
    ".bz2": (b"BZh",),
    ".xz": (b"\xfd7zXZ\x00",),
    ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
}

DEFAULT_ACTOR = "operator"

SLA_POLICIES = {
    "critical": {"response_minutes": 15, "resolution_minutes": 120},
    "high": {"response_minutes": 30, "resolution_minutes": 240},
    "medium": {"response_minutes": 240, "resolution_minutes": 1440},
    "low": {"response_minutes": 1440, "resolution_minutes": 4320},
    "info": {"response_minutes": 4320, "resolution_minutes": 10080},
}

ACTIVE_STATUSES = {
    "new",
    "pending",
    "assigned",
    "triaging",
    "investigating",
    "need_info",
    "waiting_info",
    "confirmed",
}
CLOSED_STATUSES = {"closed", "escalated"}

CORRELATION_ENTITY_WEIGHTS = {
    "hash": 70,
    "url": 60,
    "domain": 45,
    "ip": 35,
    "host": 32,
    "user": 28,
    "process": 24,
    "file_path": 35,
    "indicator": 25,
}

CORRELATION_FIELD_WEIGHTS = {
    "file_hash": 70,
    "url": 60,
    "domain": 45,
    "destination_ip": 28,
    "source_ip": 24,
    "hostname": 32,
    "username": 28,
    "process_name": 24,
    "file_path": 35,
    "rule_id": 30,
    "rule_name": 24,
}

STATUS_VALUES = {
    "new": "新建",
    "pending": "待研判",
    "assigned": "已分派",
    "triaging": "初筛中",
    "investigating": "研判中",
    "need_info": "待补充信息",
    "waiting_info": "待补充信息",
    "confirmed": "已确认",
    "closed": "已关闭",
    "escalated": "已升级事件",
}

CONCLUSION_VALUES = {
    "true_positive": "真实攻击",
    "suspicious": "疑似攻击",
    "false_positive": "误报",
    "duplicate": "重复告警",
    "business": "正常业务",
    "unknown": "无法确认",
}

SEVERITY_VALUES = {"critical", "high", "medium", "low", "info"}

ALERT_SOURCE_TEMPLATES = {
    "edr": {
        "label": "EDR / 终端检测",
        "description": "侧重主机、进程、命令行、文件和执行上下文。",
        "fields": [
            {"key": "hostname", "label": "主机名", "required": True},
            {"key": "username", "label": "用户名"},
            {"key": "process_name", "label": "进程名"},
            {"key": "command_line", "label": "命令行", "wide": True},
            {"key": "file_path", "label": "文件路径", "wide": True},
            {"key": "file_hash", "label": "文件 Hash"},
            {"key": "source_ip", "label": "主机 IP"},
            {"key": "destination_ip", "label": "远端 IP"},
            {"key": "rule_id", "label": "规则 ID"},
        ],
    },
    "hids": {
        "label": "HIDS / 主机入侵检测",
        "description": "侧重受影响主机、账号、文件变化、进程和检测规则。",
        "fields": [
            {"key": "hostname", "label": "主机名", "required": True},
            {"key": "username", "label": "用户名"},
            {"key": "process_name", "label": "进程名"},
            {"key": "command_line", "label": "命令行", "wide": True},
            {"key": "file_path", "label": "文件路径", "wide": True},
            {"key": "file_hash", "label": "文件 Hash"},
            {"key": "event_action", "label": "检测动作"},
            {"key": "rule_name", "label": "规则名称"},
            {"key": "rule_id", "label": "规则 ID"},
        ],
    },
    "ndr": {
        "label": "流量探针 / NDR",
        "description": "侧重通信两端、端口、协议、域名和 URL，不要求文件信息。",
        "fields": [
            {"key": "source_ip", "label": "源 IP", "required": True},
            {"key": "source_port", "label": "源端口"},
            {"key": "destination_ip", "label": "目的 IP", "required": True},
            {"key": "destination_port", "label": "目的端口"},
            {"key": "protocol", "label": "协议"},
            {"key": "domain", "label": "域名"},
            {"key": "url", "label": "URL", "wide": True},
            {"key": "rule_name", "label": "规则名称"},
            {"key": "rule_id", "label": "规则 ID"},
        ],
    },
    "waf": {
        "label": "WAF / Web 安全设备",
        "description": "侧重访问源、站点、请求 URL、HTTP 方法和响应状态。",
        "fields": [
            {"key": "source_ip", "label": "源 IP", "required": True},
            {"key": "destination_ip", "label": "站点 IP"},
            {"key": "domain", "label": "站点域名"},
            {"key": "url", "label": "请求 URL", "required": True, "wide": True},
            {"key": "http_method", "label": "HTTP 方法"},
            {"key": "http_status", "label": "响应状态"},
            {"key": "user_agent", "label": "User-Agent", "wide": True},
            {"key": "rule_name", "label": "规则名称"},
            {"key": "rule_id", "label": "规则 ID"},
        ],
    },
    "siem": {
        "label": "SIEM / 综合告警",
        "description": "适合已聚合的跨设备告警，字段保持相对通用。",
        "fields": [
            {"key": "hostname", "label": "主机名"},
            {"key": "username", "label": "用户名"},
            {"key": "source_ip", "label": "源 IP"},
            {"key": "destination_ip", "label": "目的 IP"},
            {"key": "domain", "label": "域名"},
            {"key": "file_hash", "label": "文件 Hash"},
            {"key": "rule_name", "label": "规则名称"},
            {"key": "rule_id", "label": "规则 ID"},
        ],
    },
    "other": {
        "label": "其他 / 通用",
        "description": "不限定设备类型，仅填写实际存在的字段。",
        "fields": [
            {"key": "hostname", "label": "主机名"},
            {"key": "username", "label": "用户名"},
            {"key": "source_ip", "label": "源 IP"},
            {"key": "destination_ip", "label": "目的 IP"},
            {"key": "domain", "label": "域名"},
            {"key": "url", "label": "URL", "wide": True},
            {"key": "file_hash", "label": "文件 Hash"},
            {"key": "file_path", "label": "文件路径", "wide": True},
            {"key": "process_name", "label": "进程名"},
            {"key": "command_line", "label": "命令行", "wide": True},
            {"key": "rule_id", "label": "规则 ID"},
        ],
    },
}


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).replace("Z", "+00:00")
        result = datetime.fromisoformat(text)
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _sla_info(item: Dict[str, Any]) -> Dict[str, Any]:
    severity = item.get("severity") or "medium"
    policy = SLA_POLICIES.get(severity, SLA_POLICIES["medium"])
    status = item.get("status") or "pending"
    created_at = _parse_time(item.get("created_at") or item.get("discovered_at"))
    if not created_at:
        return {
            "stage": "unknown",
            "status": "unknown",
            "label": "未知",
            "due_at": "",
            "remaining_seconds": None,
            "is_overdue": False,
        }

    if status in CLOSED_STATUSES:
        stage = "closed"
        due_at = created_at + timedelta(minutes=policy["resolution_minutes"])
    elif status in {"new", "pending", "assigned"}:
        stage = "response"
        due_at = created_at + timedelta(minutes=policy["response_minutes"])
    else:
        stage = "resolution"
        due_at = created_at + timedelta(minutes=policy["resolution_minutes"])

    now = datetime.now(timezone.utc)
    remaining = int((due_at - now).total_seconds())
    if status in CLOSED_STATUSES:
        sla_status = "done"
        label = "已完成"
        is_overdue = False
    elif remaining < 0:
        sla_status = "overdue"
        label = "已超时"
        is_overdue = True
    elif remaining <= 30 * 60:
        sla_status = "warning"
        label = "即将超时"
        is_overdue = False
    else:
        sla_status = "normal"
        label = "正常"
        is_overdue = False

    return {
        "stage": stage,
        "status": sla_status,
        "label": label,
        "due_at": due_at.isoformat(),
        "remaining_seconds": remaining,
        "is_overdue": is_overdue,
        "response_minutes": policy["response_minutes"],
        "resolution_minutes": policy["resolution_minutes"],
    }


def _correlation_level(score: int) -> str:
    if score >= 90:
        return "strong"
    if score >= 55:
        return "medium"
    if score > 0:
        return "weak"
    return "none"


def _correlation_label(level: str) -> str:
    return {
        "strong": "强关联",
        "medium": "中关联",
        "weak": "弱关联",
        "none": "无关联",
    }.get(level, level)


def _title_tokens(value: str) -> set:
    tokens = set()
    for token in re.findall(r"[A-Za-z0-9_\-.]{3,}|[\u4e00-\u9fff]{2,}", value or ""):
        token = token.strip().lower()
        if token and token not in {"告警", "安全", "检测", "异常", "可疑"}:
            tokens.add(token)
    return tokens


def _time_proximity_score(left: Dict[str, Any], right: Dict[str, Any]) -> Tuple[int, str]:
    left_time = _parse_time(left.get("occurred_at") or left.get("created_at"))
    right_time = _parse_time(right.get("occurred_at") or right.get("created_at"))
    if not left_time or not right_time:
        return 0, ""
    hours = abs((left_time - right_time).total_seconds()) / 3600
    if hours <= 1:
        return 15, "1 小时内发生"
    if hours <= 24:
        return 10, "24 小时内发生"
    if hours <= 72:
        return 5, "72 小时内发生"
    return 0, ""


def _reason(key: str, label: str, weight: int, value: str = "") -> Dict[str, Any]:
    return {"key": key, "label": label, "weight": weight, "value": value}


def _id(prefix: str = "") -> str:
    value = uuid.uuid4().hex[:12]
    return f"{prefix}{value}" if prefix else value


def _ensure_dirs(subdir: str = "") -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    root = Path(UPLOAD_BASE)
    path = root / subdir if subdir else root
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _safe_filename(original_name: str) -> str:
    ext = Path(original_name or "attachment").suffix.lower()
    safe = secure_filename(original_name or "attachment")
    stem = Path(safe).stem[:60] or "attachment"
    return f"{uuid.uuid4().hex[:12]}_{stem}{ext}"


def _json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def _json_loads(value: Any, fallback: Any = None) -> Any:
    if value is None or value == "":
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _conn() -> sqlite3.Connection:
    _ensure_dirs()
    conn = sqlite3.connect(DB_PATH, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    # Local single-process mode: this managed workspace rejects SQLite rollback
    # journal writes/renames. Production should move this store to PostgreSQL.
    conn.execute("PRAGMA journal_mode = OFF")
    conn.execute("PRAGMA locking_mode = EXCLUSIVE")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with _conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source_category TEXT NOT NULL DEFAULT 'other',
                source_system TEXT,
                source_product TEXT,
                alert_type TEXT,
                severity TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'pending',
                conclusion TEXT,
                close_reason TEXT,
                owner TEXT,
                created_by TEXT,
                updated_by TEXT,
                occurred_at TEXT,
                discovered_at TEXT,
                description TEXT,
                key_evidence TEXT,
                handling_suggestion TEXT,
                raw_content TEXT,
                normalized_fields TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                alert_id TEXT,
                file_type TEXT,
                filename TEXT NOT NULL,
                original_name TEXT,
                rel_path TEXT NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                mime TEXT,
                description TEXT,
                uploaded_by TEXT,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                value TEXT NOT NULL,
                role TEXT DEFAULT 'indicator',
                confidence REAL DEFAULT 1.0,
                source TEXT DEFAULT 'auto',
                created_at TEXT NOT NULL,
                UNIQUE(alert_id, entity_type, value, role),
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notes (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                author TEXT,
                note_type TEXT NOT NULL DEFAULT 'manual',
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS assignment_logs (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                assigned_by TEXT,
                from_owner TEXT,
                to_owner TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS escalation_records (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                escalated_by TEXT,
                target_team TEXT,
                severity TEXT,
                reason TEXT,
                action_required TEXT,
                due_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                actor TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                before_data TEXT,
                after_data TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_updated_at ON alerts(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_entities_value ON entities(value);
            CREATE INDEX IF NOT EXISTS idx_attachments_alert ON attachments(alert_id);
            CREATE INDEX IF NOT EXISTS idx_assignment_alert ON assignment_logs(alert_id);
            CREATE INDEX IF NOT EXISTS idx_escalation_alert ON escalation_records(alert_id);
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
        if "source_category" not in columns:
            conn.execute(
                "ALTER TABLE alerts ADD COLUMN source_category TEXT NOT NULL DEFAULT 'other'"
            )
        if "key_evidence" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN key_evidence TEXT")
        if "handling_suggestion" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN handling_suggestion TEXT")


def _row_to_alert(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["raw_content"] = _json_loads(item.get("raw_content"), {})
    item["normalized_fields"] = _json_loads(item.get("normalized_fields"), {})
    item["status_label"] = STATUS_VALUES.get(item.get("status"), item.get("status"))
    item["conclusion_label"] = CONCLUSION_VALUES.get(item.get("conclusion"), item.get("conclusion") or "")
    item["source"] = item.get("source_system") or ""
    item["host"] = item["normalized_fields"].get("hostname", "")
    item["rule_id"] = item["normalized_fields"].get("rule_id", "")
    item["timestamp"] = item.get("occurred_at")
    item["upload_time"] = item.get("created_at")
    item["raw_size"] = len(_json_dumps(item["raw_content"]))
    item["source_category"] = item.get("source_category") or "other"
    item["source_category_label"] = ALERT_SOURCE_TEMPLATES.get(
        item["source_category"], ALERT_SOURCE_TEMPLATES["other"]
    )["label"]
    item["sla"] = _sla_info(item)
    return item


def _row_to_attachment(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["url"] = f"/api/incident/files/{item['rel_path'].replace(os.sep, '/')}"
    item["upload_time"] = item.get("uploaded_at")
    return item


def _row_to_entity(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def _row_to_note(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def _row_to_assignment(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def _row_to_escalation(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def _row_to_audit(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["before_data"] = _json_loads(item.get("before_data"), {})
    item["after_data"] = _json_loads(item.get("after_data"), {})
    return item


def _audit(
    action: str,
    target_type: str,
    target_id: Optional[str],
    actor: str = DEFAULT_ACTOR,
    before: Any = None,
    after: Any = None,
) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_logs
            (id, actor, action, target_type, target_id, before_data, after_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (_id("aud_"), actor, action, target_type, target_id, _json_dumps(before), _json_dumps(after), _now()),
        )


def _record_assignment(
    alert_id: str,
    assigned_by: str,
    from_owner: str,
    to_owner: str,
) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO assignment_logs
            (id, alert_id, assigned_by, from_owner, to_owner, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (_id("asn_"), alert_id, assigned_by, from_owner or "", to_owner or "", _now()),
        )


def _first(raw: Dict[str, Any], keys: List[str], default: str = "") -> str:
    for key in keys:
        value = raw.get(key)
        if value is not None and value != "":
            return str(value)
    return default


def _normalize_severity(value: Any) -> str:
    text = str(value or "medium").lower()
    mapping = {
        "严重": "critical",
        "高": "high",
        "中": "medium",
        "低": "low",
        "信息": "info",
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    if text.isdigit():
        score = int(text)
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
    return mapping.get(text, "medium")


def _normalize_alert(raw: Dict[str, Any]) -> Dict[str, Any]:
    host = _first(raw, ["hostname", "host", "asset", "asset_name", "computer_name"])
    agent = raw.get("agent")
    if not host and isinstance(agent, dict):
        host = _first(agent, ["hostname", "name", "id"])

    normalized = {
        "source_ip": _first(raw, ["source_ip", "src_ip", "sip", "attacker_ip", "client_ip"]),
        "destination_ip": _first(raw, ["destination_ip", "dst_ip", "dip", "victim_ip", "server_ip"]),
        "source_port": _first(raw, ["source_port", "src_port", "sport"]),
        "destination_port": _first(raw, ["destination_port", "dst_port", "dport"]),
        "hostname": host,
        "username": _first(raw, ["username", "user", "account", "login_user"]),
        "domain": _first(raw, ["domain", "dns", "fqdn"]),
        "url": _first(raw, ["url", "uri", "request_url"]),
        "file_hash": _first(raw, ["file_hash", "hash", "sha256", "sha1", "md5"]),
        "file_path": _first(raw, ["file_path", "path", "image_path"]),
        "process_name": _first(raw, ["process_name", "process", "image", "proc_name"]),
        "command_line": _first(raw, ["command_line", "cmdline", "cmd", "process_cmd"]),
        "rule_name": _first(raw, ["rule_name", "rule", "signature", "detection_name", "name"]),
        "rule_id": _first(raw, ["rule_id", "ruleId", "signature_id", "event_id", "id"]),
        "protocol": _first(raw, ["protocol", "network_protocol", "transport"]),
        "http_method": _first(raw, ["http_method", "method", "request_method"]),
        "http_status": _first(raw, ["http_status", "status_code", "response_code"]),
        "user_agent": _first(raw, ["user_agent", "user-agent", "http_user_agent"]),
        "event_action": _first(raw, ["event_action", "action", "operation"]),
    }

    source_category = _first(
        raw,
        ["source_category", "device_type", "security_device_type"],
        "other",
    ).lower()
    aliases = {
        "traffic": "ndr",
        "probe": "ndr",
        "ids": "ndr",
        "ips": "ndr",
        "endpoint": "edr",
        "host": "hids",
    }
    source_category = aliases.get(source_category, source_category)
    if source_category not in ALERT_SOURCE_TEMPLATES:
        source_category = "other"

    return {
        "title": _first(raw, ["title", "alert_title", "name", "rule", "alert"], "未命名告警"),
        "source_category": source_category,
        "source_system": _first(raw, ["source_system", "source", "detector", "from", "vendor"], "手工录入"),
        "source_product": _first(raw, ["source_product", "product", "platform"]),
        "alert_type": _first(raw, ["alert_type", "type", "category", "threat_type"]),
        "severity": _normalize_severity(_first(raw, ["severity", "level", "priority", "risk_level"], "medium")),
        "occurred_at": _first(raw, ["occurred_at", "timestamp", "time", "@timestamp", "alert_time"], _now()),
        "discovered_at": _first(raw, ["discovered_at", "created_at", "detect_time"], _now()),
        "description": _first(raw, ["description", "message", "desc", "detail", "details"]),
        "normalized_fields": normalized,
    }


ENTITY_PATTERNS = [
    ("hash", re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")),
    ("url", re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")),
    ("file_path", re.compile(r"(?:[A-Za-z]:\\[^\s\"'<>]+|/[A-Za-z0-9._/\-]+)")),
]


def extract_entities(raw: Any, normalized: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    text = raw if isinstance(raw, str) else _json_dumps(raw)
    results: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    explicit = {
        "source_ip": ("ip", "source"),
        "destination_ip": ("ip", "destination"),
        "hostname": ("host", "affected"),
        "username": ("user", "affected"),
        "domain": ("domain", "indicator"),
        "url": ("url", "indicator"),
        "file_hash": ("hash", "indicator"),
        "file_path": ("file_path", "indicator"),
        "process_name": ("process", "indicator"),
    }
    for key, (entity_type, role) in explicit.items():
        value = (normalized or {}).get(key)
        if value:
            results[(entity_type, str(value), role)] = {
                "entity_type": entity_type,
                "value": str(value),
                "role": role,
                "confidence": 1.0,
                "source": "field",
            }

    for entity_type, pattern in ENTITY_PATTERNS:
        for value in pattern.findall(text):
            if entity_type == "domain" and value.startswith("http"):
                continue
            results.setdefault(
                (entity_type, value, "indicator"),
                {
                    "entity_type": entity_type,
                    "value": value,
                    "role": "indicator",
                    "confidence": 0.8,
                    "source": "auto",
                },
            )

    return list(results.values())


def create_alert(raw: Dict[str, Any], actor: str = DEFAULT_ACTOR) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("告警内容必须是 JSON 对象")
    init_db()

    normalized_alert = _normalize_alert(raw)
    alert_id = _id("alt_")
    now = _now()
    normalized_fields = normalized_alert["normalized_fields"]

    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO alerts (
                id, title, source_category, source_system, source_product, alert_type, severity, status,
                conclusion, close_reason, owner, created_by, updated_by, occurred_at,
                discovered_at, description, key_evidence, handling_suggestion,
                raw_content, normalized_fields, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                normalized_alert["title"],
                normalized_alert["source_category"],
                normalized_alert["source_system"],
                normalized_alert["source_product"],
                normalized_alert["alert_type"],
                normalized_alert["severity"],
                raw.get("status") or "pending",
                raw.get("conclusion") or "",
                raw.get("close_reason") or "",
                raw.get("owner") or "",
                raw.get("reporter") or raw.get("created_by") or actor,
                actor,
                normalized_alert["occurred_at"],
                normalized_alert["discovered_at"],
                normalized_alert["description"],
                raw.get("key_evidence") or "",
                raw.get("handling_suggestion") or "",
                _json_dumps(raw),
                _json_dumps(normalized_fields),
                now,
                now,
            ),
        )

        for entity in extract_entities(raw, normalized_fields):
            _insert_entity(conn, alert_id, entity)

        for attachment in raw.get("attachments", []) if isinstance(raw.get("attachments"), list) else []:
            if isinstance(attachment, dict) and attachment.get("url"):
                _insert_external_attachment(conn, alert_id, attachment, actor)

    _audit("create_alert", "alert", alert_id, actor, after={"id": alert_id, "title": normalized_alert["title"]})
    add_note(alert_id, "告警已创建", "system", actor, audit=False)
    return get_alert(alert_id) or {}


def _insert_entity(conn: sqlite3.Connection, alert_id: str, entity: Dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO entities
        (id, alert_id, entity_type, value, role, confidence, source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _id("ent_"),
            alert_id,
            entity.get("entity_type", "unknown"),
            str(entity.get("value", ""))[:500],
            entity.get("role", "indicator"),
            float(entity.get("confidence", 1.0)),
            entity.get("source", "manual"),
            _now(),
        ),
    )


def _insert_external_attachment(
    conn: sqlite3.Connection,
    alert_id: Optional[str],
    attachment: Dict[str, Any],
    actor: str,
) -> None:
    url = attachment.get("url", "")
    rel_path = url.split("/api/incident/files/")[-1] if "/api/incident/files/" in url else url
    filename = attachment.get("filename") or Path(rel_path).name or "attachment"
    ext = Path(filename).suffix.lower()
    conn.execute(
        """
        INSERT INTO attachments
        (id, alert_id, file_type, filename, original_name, rel_path, size, mime, description, uploaded_by, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _id("att_"),
            alert_id,
            "image" if ext in ALLOWED_IMAGE_EXT else "other",
            filename,
            attachment.get("original_name") or filename,
            rel_path,
            int(attachment.get("size") or 0),
            attachment.get("mime") or "",
            attachment.get("description") or "",
            actor,
            attachment.get("uploaded_at") or attachment.get("upload_time") or _now(),
        ),
    )


def list_alerts(filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    init_db()
    filters = filters or {}
    clauses = []
    params: List[Any] = []
    queue = filters.get("queue") or "all"
    current_user = filters.get("current_user") or DEFAULT_ACTOR

    mapping = {
        "source_category": "source_category",
        "status": "status",
        "severity": "severity",
        "conclusion": "conclusion",
        "owner": "owner",
        "reporter": "created_by",
        "source_system": "source_system",
    }
    for key, column in mapping.items():
        value = filters.get(key)
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)

    if queue == "my":
        clauses.append("owner = ?")
        params.append(current_user)
        clauses.append(f"status NOT IN ({','.join(['?'] * len(CLOSED_STATUSES))})")
        params.extend(sorted(CLOSED_STATUSES))
    elif queue == "unassigned":
        clauses.append("(owner IS NULL OR owner = '')")
        clauses.append(f"status NOT IN ({','.join(['?'] * len(CLOSED_STATUSES))})")
        params.extend(sorted(CLOSED_STATUSES))
    elif queue == "active":
        clauses.append(f"status IN ({','.join(['?'] * len(ACTIVE_STATUSES))})")
        params.extend(sorted(ACTIVE_STATUSES))
    elif queue == "closed":
        clauses.append("status = ?")
        params.append("closed")
    elif queue == "escalated":
        clauses.append("status = ?")
        params.append("escalated")

    keyword = filters.get("keyword")
    if keyword:
        clauses.append(
            "(title LIKE ? OR source_system LIKE ? OR description LIKE ? OR normalized_fields LIKE ? OR raw_content LIKE ?)"
        )
        like = f"%{keyword}%"
        params.extend([like, like, like, like, like])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit = int(filters.get("limit") or 200)
    offset = int(filters.get("offset") or 0)
    db_limit = 10000 if queue == "overdue" else limit

    with _conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [db_limit, offset],
        ).fetchall()
        alerts = [_row_to_alert(r) for r in rows]
        for alert in alerts:
            alert["entity_count"] = conn.execute(
                "SELECT count(*) AS c FROM entities WHERE alert_id = ?", (alert["id"],)
            ).fetchone()["c"]
            alert["attachment_count"] = conn.execute(
                "SELECT count(*) AS c FROM attachments WHERE alert_id = ?", (alert["id"],)
            ).fetchone()["c"]
    if queue == "overdue":
        alerts = [alert for alert in alerts if alert.get("sla", {}).get("is_overdue")]
        alerts = alerts[:limit]
    return alerts


def get_alert(alert_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _conn() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return None
        alert = _row_to_alert(row)
        alert["attachments"] = [
            _row_to_attachment(r)
            for r in conn.execute("SELECT * FROM attachments WHERE alert_id = ? ORDER BY uploaded_at DESC", (alert_id,))
        ]
        alert["entities"] = [
            _row_to_entity(r)
            for r in conn.execute("SELECT * FROM entities WHERE alert_id = ? ORDER BY entity_type, value", (alert_id,))
        ]
        alert["notes"] = [
            _row_to_note(r)
            for r in conn.execute("SELECT * FROM notes WHERE alert_id = ? ORDER BY created_at DESC", (alert_id,))
        ]
        alert["assignments"] = [
            _row_to_assignment(r)
            for r in conn.execute(
                "SELECT * FROM assignment_logs WHERE alert_id = ? ORDER BY created_at DESC",
                (alert_id,),
            )
        ]
        alert["escalations"] = [
            _row_to_escalation(r)
            for r in conn.execute(
                "SELECT * FROM escalation_records WHERE alert_id = ? ORDER BY created_at DESC",
                (alert_id,),
            )
        ]
        alert["audit"] = [
            _row_to_audit(r)
            for r in conn.execute(
                "SELECT * FROM audit_logs WHERE target_id = ? ORDER BY created_at DESC LIMIT 100",
                (alert_id,),
            )
        ]
        correlation = get_alert_correlation(alert_id, limit=8) or {
            "summary": {},
            "entity_profiles": [],
            "related_alerts": [],
        }
        alert["correlation"] = correlation
        alert["related"] = correlation["related_alerts"]
        return alert


def update_alert(alert_id: str, data: Dict[str, Any], actor: str = DEFAULT_ACTOR) -> Optional[Dict[str, Any]]:
    init_db()
    allowed = {
        "title",
        "source_category",
        "source_system",
        "source_product",
        "alert_type",
        "severity",
        "status",
        "conclusion",
        "close_reason",
        "owner",
        "created_by",
        "occurred_at",
        "discovered_at",
        "description",
        "key_evidence",
        "handling_suggestion",
    }
    before = get_alert(alert_id)
    if not before:
        return None

    updates = []
    params: List[Any] = []
    for key in allowed:
        if key in data:
            value = data[key]
            if key == "severity":
                value = _normalize_severity(value)
            updates.append(f"{key} = ?")
            params.append(value)

    normalized = dict(before.get("normalized_fields") or {})
    for key in [
        "source_ip",
        "destination_ip",
        "hostname",
        "username",
        "domain",
        "url",
        "file_hash",
        "file_path",
        "process_name",
        "command_line",
        "rule_name",
        "rule_id",
        "protocol",
        "http_method",
        "http_status",
        "user_agent",
        "event_action",
    ]:
        if key in data:
            normalized[key] = data.get(key) or ""
    if normalized != before.get("normalized_fields"):
        updates.append("normalized_fields = ?")
        params.append(_json_dumps(normalized))

    if not updates:
        return before

    updates.append("updated_by = ?")
    updates.append("updated_at = ?")
    params.extend([actor, _now(), alert_id])

    with _conn() as conn:
        conn.execute(f"UPDATE alerts SET {', '.join(updates)} WHERE id = ?", params)
        if normalized != before.get("normalized_fields"):
            for entity in extract_entities(data, normalized):
                _insert_entity(conn, alert_id, entity)

    after = get_alert(alert_id)
    if "owner" in data and (before.get("owner") or "") != (after.get("owner") or ""):
        from_owner = before.get("owner") or ""
        to_owner = after.get("owner") or ""
        _record_assignment(alert_id, actor, from_owner, to_owner)
        add_note(
            alert_id,
            f"告警分派：{from_owner or '未分派'} -> {to_owner or '未分派'}，分派人：{actor}",
            "assignment",
            actor,
            audit=False,
        )
        _audit(
            "assign_alert",
            "alert",
            alert_id,
            actor,
            before={"owner": from_owner},
            after={"from_owner": from_owner, "to_owner": to_owner, "assigned_by": actor},
        )
        after = get_alert(alert_id)
    _audit("update_alert", "alert", alert_id, actor, before=before, after=after)
    return after


def delete_alert(alert_id: str, actor: str = DEFAULT_ACTOR) -> bool:
    before = get_alert(alert_id)
    if not before:
        return False
    with _conn() as conn:
        conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    _audit("delete_alert", "alert", alert_id, actor, before=before)
    return True


def batch_update_alerts(
    alert_ids: List[str],
    action: str,
    payload: Optional[Dict[str, Any]] = None,
    actor: str = DEFAULT_ACTOR,
) -> Dict[str, Any]:
    if not isinstance(alert_ids, list) or not alert_ids:
        raise ValueError("请选择需要批量操作的告警")
    payload = payload or {}
    updated = []
    errors = []

    for alert_id in alert_ids:
        try:
            if action == "assign":
                owner = str(payload.get("owner") or "").strip()
                if not owner:
                    raise ValueError("批量分派需要指定责任人")
                result = update_alert(alert_id, {"owner": owner, "status": "assigned"}, actor)
            elif action == "status":
                status = str(payload.get("status") or "").strip()
                if status == "closed":
                    result = set_status(alert_id, status, actor, payload)
                else:
                    result = set_status(alert_id, status, actor, payload.get("reason", ""))
            elif action == "severity":
                severity = str(payload.get("severity") or "").strip()
                result = update_alert(alert_id, {"severity": severity}, actor)
            elif action == "note":
                content = str(payload.get("content") or "").strip()
                note = add_note(alert_id, content, payload.get("note_type", "batch"), actor)
                result = get_alert(alert_id) if note else None
            else:
                raise ValueError("不支持的批量操作")

            if not result:
                errors.append({"id": alert_id, "error": "告警不存在"})
            else:
                updated.append(alert_id)
        except Exception as exc:
            errors.append({"id": alert_id, "error": str(exc)})

    _audit(
        f"batch_{action}",
        "alert",
        ",".join(alert_ids[:20]),
        actor,
        after={"updated": updated, "errors": errors, "payload": payload},
    )
    return {
        "requested": len(alert_ids),
        "updated": len(updated),
        "errors": errors,
    }


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data:
        return False
    for encoding in ("utf-8", "gb18030"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        readable = sum(char.isprintable() or char in "\t\n\r" for char in text)
        return readable / max(len(text), 1) >= 0.95
    return False


def _is_log_filename(filename: str) -> bool:
    lower_name = Path(filename).name.lower()
    for compressed_ext in COMPRESSED_LOG_EXTENSIONS:
        if lower_name.endswith(compressed_ext):
            lower_name = lower_name[:-len(compressed_ext)]
            break
    if Path(lower_name).suffix in LOG_EXTENSIONS:
        return True
    if re.search(r"\.(?:log|out|txt|json|csv)(?:\.\d+|\.\d{4}[-_.]\d{1,2}[-_.]\d{1,2})?$", lower_name):
        return True
    return lower_name in {
        "access_log",
        "error_log",
        "messages",
        "syslog",
        "catalina",
        "stdout",
        "stderr",
    }


def _attachment_policy(filename: str, sample: bytes) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    lower_name = Path(filename).name.lower()
    ext = Path(lower_name).suffix

    if ext in ALLOWED_IMAGE_EXT:
        return {
            "file_type": "image",
            "subdir": "images",
            "max_size": MAX_IMAGE_SIZE,
        }, None

    if ext in PACKET_EXTENSIONS:
        valid_header = (
            sample[:4] in PCAP_MAGIC_HEADERS
            if ext == ".pcap"
            else sample[:4] == PCAPNG_MAGIC_HEADER
        )
        if not valid_header:
            return None, f"{ext} 文件头校验失败，请上传有效的流量包"
        return {
            "file_type": ext.lstrip("."),
            "subdir": "packets",
            "max_size": MAX_FORENSIC_FILE_SIZE,
        }, None

    if ext in COMPRESSED_LOG_EXTENSIONS:
        if not _is_log_filename(lower_name):
            return None, "压缩文件仅支持日志归档，例如 access.log.gz、catalina.out.gz"
        if not any(sample.startswith(header) for header in COMPRESSED_MAGIC_HEADERS[ext]):
            return None, f"{ext} 压缩文件头校验失败"
        return {
            "file_type": "log_archive",
            "subdir": "logs",
            "max_size": MAX_FORENSIC_FILE_SIZE,
        }, None

    if _is_log_filename(lower_name):
        if not _looks_like_text(sample):
            return None, "日志文件内容不是可识别的文本格式"
        return {
            "file_type": "log",
            "subdir": "logs",
            "max_size": MAX_LOG_SIZE,
        }, None

    if not ext and _looks_like_text(sample):
        return {
            "file_type": "log",
            "subdir": "logs",
            "max_size": MAX_LOG_SIZE,
        }, None

    allowed = sorted(ALLOWED_IMAGE_EXT | LOG_EXTENSIONS | PACKET_EXTENSIONS)
    return None, (
        "不支持的附件格式。支持图片、PCAP/PCAPNG、常见日志、无后缀文本日志、"
        "轮转日志及日志压缩包；常规后缀包括: " + ", ".join(allowed)
    )


def _save_stream_with_limit(file_storage, dest: Path, max_size: int) -> Tuple[int, Optional[str]]:
    total = 0
    try:
        file_storage.seek(0)
        with dest.open("wb") as output:
            while True:
                chunk = file_storage.stream.read(COPY_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    raise ValueError(
                        f"附件大小超过限制（最大 {max_size // 1024 // 1024} MB）"
                    )
                output.write(chunk)
    except Exception as exc:
        dest.unlink(missing_ok=True)
        return 0, str(exc)
    finally:
        file_storage.seek(0)
    return total, None


def save_attachment(
    file_storage,
    alert_id: Optional[str] = None,
    description: str = "",
    actor: str = DEFAULT_ACTOR,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    init_db()
    filename = file_storage.filename or "attachment"
    sample = file_storage.stream.read(FILE_SAMPLE_SIZE)
    file_storage.seek(0)
    policy, policy_error = _attachment_policy(filename, sample)
    if policy_error:
        return None, policy_error

    subdir = policy["subdir"]
    saved_name = _safe_filename(filename)
    dest = Path(_ensure_dirs(subdir)) / saved_name
    size, save_error = _save_stream_with_limit(file_storage, dest, policy["max_size"])
    if save_error:
        return None, save_error

    rel_path = f"{subdir}/{saved_name}"
    file_type = policy["file_type"]
    att_id = _id("att_")
    now = _now()
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO attachments
            (id, alert_id, file_type, filename, original_name, rel_path, size, mime, description, uploaded_by, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                att_id,
                alert_id,
                file_type,
                saved_name,
                filename,
                rel_path,
                size,
                getattr(file_storage, "mimetype", "") or "",
                description,
                actor,
                now,
            ),
        )

    item = get_attachment(att_id)
    _audit("upload_attachment", "attachment", att_id, actor, after=item)
    return item, None


def save_image(file_storage):
    """兼容旧接口：保存未绑定告警的图片。"""
    return save_attachment(file_storage, alert_id=None)


def get_attachment(attachment_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _conn() as conn:
        row = conn.execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
    return _row_to_attachment(row) if row else None


def list_attachments(alert_id: Optional[str] = None) -> List[Dict[str, Any]]:
    init_db()
    with _conn() as conn:
        if alert_id:
            rows = conn.execute(
                "SELECT * FROM attachments WHERE alert_id = ? ORDER BY uploaded_at DESC", (alert_id,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM attachments ORDER BY uploaded_at DESC").fetchall()
    return [_row_to_attachment(r) for r in rows]


def list_images() -> List[Dict[str, Any]]:
    return [a for a in list_attachments() if a.get("file_type") == "image"]


def delete_attachment(attachment_id: str, actor: str = DEFAULT_ACTOR) -> bool:
    item = get_attachment(attachment_id)
    if not item:
        return False
    full = resolve_file_path(item["rel_path"])
    with _conn() as conn:
        conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
    if full and full.is_file():
        try:
            full.unlink()
        except OSError:
            pass
    _audit("delete_attachment", "attachment", attachment_id, actor, before=item)
    return True


def delete_image(image_id: str):
    return delete_attachment(image_id)


def add_entity(alert_id: str, entity: Dict[str, Any], actor: str = DEFAULT_ACTOR) -> Optional[Dict[str, Any]]:
    if not get_alert(alert_id):
        return None
    payload = {
        "entity_type": entity.get("entity_type") or entity.get("type") or "indicator",
        "value": entity.get("value") or "",
        "role": entity.get("role") or "indicator",
        "confidence": float(entity.get("confidence") or 1.0),
        "source": "manual",
    }
    if not payload["value"]:
        raise ValueError("实体值不能为空")
    with _conn() as conn:
        _insert_entity(conn, alert_id, payload)
        row = conn.execute(
            """
            SELECT * FROM entities
            WHERE alert_id = ? AND entity_type = ? AND value = ? AND role = ?
            """,
            (alert_id, payload["entity_type"], payload["value"], payload["role"]),
        ).fetchone()
    item = _row_to_entity(row)
    _audit("add_entity", "entity", item["id"], actor, after=item)
    return item


def delete_entity(entity_id: str, actor: str = DEFAULT_ACTOR) -> bool:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if not row:
            return False
        item = _row_to_entity(row)
        conn.execute("DELETE FROM entities WHERE id = ?", (entity_id,))
    _audit("delete_entity", "entity", entity_id, actor, before=item)
    return True


def add_note(
    alert_id: str,
    content: str,
    note_type: str = "manual",
    author: str = DEFAULT_ACTOR,
    audit: bool = True,
) -> Optional[Dict[str, Any]]:
    if not content.strip():
        raise ValueError("研判记录不能为空")
    if not get_alert(alert_id):
        return None
    note_id = _id("not_")
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO notes (id, alert_id, author, note_type, content, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (note_id, alert_id, author, note_type, content.strip(), _now()),
        )
        conn.execute("UPDATE alerts SET updated_at = ?, updated_by = ? WHERE id = ?", (_now(), author, alert_id))
        row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    item = _row_to_note(row)
    if audit:
        _audit("add_note", "note", note_id, author, after=item)
    return item


def set_status(alert_id: str, status: str, actor: str = DEFAULT_ACTOR, reason: str = "") -> Optional[Dict[str, Any]]:
    if status not in STATUS_VALUES:
        raise ValueError("状态值无效")
    before = get_alert(alert_id)
    if not before:
        return None
    update_data = {"status": status}
    note_reason = ""
    if status == "closed":
        if isinstance(reason, dict):
            close_reason = str(reason.get("close_reason") or reason.get("reason") or "").strip()
            conclusion = str(reason.get("conclusion") or "").strip()
            key_evidence = str(reason.get("key_evidence") or "").strip()
            handling_suggestion = str(reason.get("handling_suggestion") or "").strip()
        else:
            close_reason = str(reason or "").strip()
            conclusion = str(before.get("conclusion") or "").strip()
            key_evidence = str(before.get("key_evidence") or "").strip()
            handling_suggestion = str(before.get("handling_suggestion") or "").strip()
        if not conclusion:
            raise ValueError("关闭告警前必须填写研判结论")
        if conclusion not in CONCLUSION_VALUES:
            raise ValueError("结论值无效")
        if not close_reason:
            raise ValueError("关闭告警前必须填写关闭原因")
        if not key_evidence:
            raise ValueError("关闭告警前必须填写关键依据")
        update_data.update({
            "conclusion": conclusion,
            "close_reason": close_reason,
            "key_evidence": key_evidence,
            "handling_suggestion": handling_suggestion,
        })
        note_reason = close_reason
    else:
        update_data["close_reason"] = ""
        note_reason = str(reason or "")
    updated = update_alert(alert_id, update_data, actor)
    add_note(alert_id, f"状态变更：{before.get('status_label')} -> {STATUS_VALUES[status]}{('，原因：' + note_reason) if note_reason else ''}", "status_change", actor, audit=False)
    return updated


def set_conclusion(
    alert_id: str,
    conclusion: str,
    actor: str = DEFAULT_ACTOR,
    content: str = "",
) -> Optional[Dict[str, Any]]:
    if conclusion and conclusion not in CONCLUSION_VALUES:
        raise ValueError("结论值无效")
    updated = update_alert(alert_id, {"conclusion": conclusion}, actor)
    if updated:
        label = CONCLUSION_VALUES.get(conclusion, conclusion)
        add_note(alert_id, f"研判结论：{label}{('。' + content) if content else ''}", "conclusion", actor, audit=False)
    return updated


def escalate_alert(alert_id: str, payload: Dict[str, Any], actor: str = DEFAULT_ACTOR) -> Optional[Dict[str, Any]]:
    before = get_alert(alert_id)
    if not before:
        return None
    target_team = str(payload.get("target_team") or "").strip()
    reason = str(payload.get("reason") or "").strip()
    action_required = str(payload.get("action_required") or "").strip()
    severity = str(payload.get("severity") or before.get("severity") or "high").strip()
    due_at = str(payload.get("due_at") or "").strip()
    if not target_team:
        raise ValueError("升级事件需要指定接收团队")
    if not reason:
        raise ValueError("升级事件需要填写升级原因")
    if severity not in SEVERITY_VALUES:
        raise ValueError("升级等级无效")

    record_id = _id("esc_")
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO escalation_records
            (id, alert_id, escalated_by, target_team, severity, reason, action_required, due_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (record_id, alert_id, actor, target_team, severity, reason, action_required, due_at, _now()),
        )

    update_data = {"status": "escalated", "severity": severity}
    if not before.get("conclusion"):
        update_data["conclusion"] = "suspicious"
    after = update_alert(alert_id, update_data, actor)
    add_note(
        alert_id,
        f"升级事件：接收团队 {target_team}，等级 {severity}，原因：{reason}"
        + (f"，处置要求：{action_required}" if action_required else ""),
        "escalation",
        actor,
        audit=False,
    )
    _audit(
        "escalate_alert",
        "alert",
        alert_id,
        actor,
        before={"status": before.get("status"), "severity": before.get("severity")},
        after={
            "record_id": record_id,
            "target_team": target_team,
            "severity": severity,
            "reason": reason,
            "action_required": action_required,
            "due_at": due_at,
        },
    )
    return get_alert(alert_id) if after else None


def get_alert_correlation(alert_id: str, limit: int = 20) -> Optional[Dict[str, Any]]:
    init_db()
    with _conn() as conn:
        base_row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not base_row:
            return None
        base_alert = _row_to_alert(base_row)
        base_entities = [
            _row_to_entity(row)
            for row in conn.execute("SELECT * FROM entities WHERE alert_id = ?", (alert_id,))
        ]
        candidate_rows = conn.execute(
            "SELECT * FROM alerts WHERE id != ? ORDER BY updated_at DESC LIMIT 1000",
            (alert_id,),
        ).fetchall()
        candidate_ids = [row["id"] for row in candidate_rows]

        entity_map: Dict[str, List[Dict[str, Any]]] = {candidate_id: [] for candidate_id in candidate_ids}
        if candidate_ids:
            placeholders = ",".join(["?"] * len(candidate_ids))
            for row in conn.execute(
                f"SELECT * FROM entities WHERE alert_id IN ({placeholders})",
                candidate_ids,
            ):
                entity_map.setdefault(row["alert_id"], []).append(_row_to_entity(row))

        entity_profiles = []
        for entity in base_entities:
            rows = conn.execute(
                """
                SELECT DISTINCT a.id, a.title, a.status, a.severity, a.updated_at
                FROM alerts a
                JOIN entities e ON e.alert_id = a.id
                WHERE e.entity_type = ? AND e.value = ?
                ORDER BY a.updated_at DESC
                LIMIT 6
                """,
                (entity["entity_type"], entity["value"]),
            ).fetchall()
            status_counter = Counter(row["status"] for row in rows)
            entity_profiles.append(
                {
                    "entity_type": entity["entity_type"],
                    "value": entity["value"],
                    "role": entity.get("role", "indicator"),
                    "alert_count": len(rows),
                    "status_counts": dict(status_counter),
                    "recent_alerts": [dict(row) for row in rows],
                }
            )

    base_normalized = base_alert.get("normalized_fields") or {}
    base_entity_keys = {
        (entity.get("entity_type"), str(entity.get("value") or "").lower()): entity
        for entity in base_entities
        if entity.get("value")
    }
    base_title_tokens = _title_tokens(f"{base_alert.get('title') or ''} {base_alert.get('alert_type') or ''}")

    related: List[Dict[str, Any]] = []
    for row in candidate_rows:
        candidate = _row_to_alert(row)
        normalized = candidate.get("normalized_fields") or {}
        reasons: List[Dict[str, Any]] = []
        matched_entities = []

        for entity in entity_map.get(candidate["id"], []):
            key = (entity.get("entity_type"), str(entity.get("value") or "").lower())
            if key in base_entity_keys:
                weight = CORRELATION_ENTITY_WEIGHTS.get(entity.get("entity_type"), 20)
                value = str(entity.get("value") or "")
                matched_entities.append(value)
                reasons.append(
                    _reason(
                        f"entity:{entity.get('entity_type')}",
                        f"共享实体 {entity.get('entity_type')}",
                        weight,
                        value,
                    )
                )

        for field, weight in CORRELATION_FIELD_WEIGHTS.items():
            left = str(base_normalized.get(field) or "").strip()
            right = str(normalized.get(field) or "").strip()
            if left and right and left.lower() == right.lower():
                reasons.append(_reason(f"field:{field}", f"相同字段 {field}", weight, left))

        if base_alert.get("source_category") and base_alert.get("source_category") == candidate.get("source_category"):
            reasons.append(_reason("source_category", "相同安全设备类型", 6, base_alert.get("source_category") or ""))
        if base_alert.get("alert_type") and base_alert.get("alert_type") == candidate.get("alert_type"):
            reasons.append(_reason("alert_type", "相同告警类型", 12, base_alert.get("alert_type") or ""))
        if base_alert.get("source_system") and base_alert.get("source_system") == candidate.get("source_system"):
            reasons.append(_reason("source_system", "相同来源系统", 6, base_alert.get("source_system") or ""))

        shared_tokens = base_title_tokens & _title_tokens(f"{candidate.get('title') or ''} {candidate.get('alert_type') or ''}")
        if shared_tokens:
            reasons.append(_reason("title", "标题/类型关键词相似", min(15, len(shared_tokens) * 5), ", ".join(sorted(shared_tokens)[:4])))

        time_score, time_label = _time_proximity_score(base_alert, candidate)
        if time_score:
            reasons.append(_reason("time", time_label, time_score))

        has_quality_reason = any(
            reason["key"].startswith("entity:")
            or reason["key"].startswith("field:")
            or reason["key"] in {"alert_type", "title"}
            for reason in reasons
        )
        score = min(100, sum(reason["weight"] for reason in reasons))
        if score <= 0 or not has_quality_reason:
            continue

        reasons = sorted(reasons, key=lambda item: item["weight"], reverse=True)
        level = _correlation_level(score)
        candidate.update(
            {
                "correlation_score": score,
                "correlation_level": level,
                "correlation_label": _correlation_label(level),
                "correlation_reasons": reasons[:8],
                "match_count": len(set(matched_entities)),
                "matched_entities": sorted(set(matched_entities)),
            }
        )
        related.append(candidate)

    related.sort(key=lambda item: (item.get("correlation_score", 0), item.get("updated_at") or ""), reverse=True)
    related = related[:limit]
    level_counts = Counter(item.get("correlation_level", "none") for item in related)
    top_reasons = Counter()
    for item in related:
        for reason in item.get("correlation_reasons", []):
            top_reasons[reason["label"]] += 1

    summary = {
        "related_count": len(related),
        "strong_count": level_counts.get("strong", 0),
        "medium_count": level_counts.get("medium", 0),
        "weak_count": level_counts.get("weak", 0),
        "top_score": related[0]["correlation_score"] if related else 0,
        "top_reasons": [{"label": label, "count": count} for label, count in top_reasons.most_common(6)],
        "suggestion": "建议合并为同一事件或同一攻击链继续研判" if level_counts.get("strong", 0) else (
            "建议优先核查共享实体和时间接近的告警" if related else "暂未发现可用关联线索"
        ),
    }
    entity_profiles.sort(key=lambda item: item["alert_count"], reverse=True)
    return {
        "summary": summary,
        "entity_profiles": entity_profiles,
        "related_alerts": related,
    }


def get_related_alerts(alert_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    correlation = get_alert_correlation(alert_id, limit=limit)
    if not correlation:
        return []
    return correlation["related_alerts"]


def get_stats() -> Dict[str, Any]:
    init_db()
    with _conn() as conn:
        total = conn.execute("SELECT count(*) AS c FROM alerts").fetchone()["c"]
        by_status = {
            STATUS_VALUES.get(r["status"], r["status"]): r["c"]
            for r in conn.execute("SELECT status, count(*) AS c FROM alerts GROUP BY status")
        }
        by_severity = {
            r["severity"]: r["c"] for r in conn.execute("SELECT severity, count(*) AS c FROM alerts GROUP BY severity")
        }
        by_source = {
            r["source_system"] or "未知": r["c"]
            for r in conn.execute("SELECT source_system, count(*) AS c FROM alerts GROUP BY source_system")
        }
        by_category = {
            r["source_category"] or "other": r["c"]
            for r in conn.execute("SELECT source_category, count(*) AS c FROM alerts GROUP BY source_category")
        }
        pending = conn.execute(
            "SELECT count(*) AS c FROM alerts WHERE status IN ('new','pending','assigned','triaging','investigating','need_info','waiting_info','confirmed')"
        ).fetchone()["c"]
        unassigned = conn.execute(
            "SELECT count(*) AS c FROM alerts WHERE (owner IS NULL OR owner = '') AND status NOT IN ('closed','escalated')"
        ).fetchone()["c"]
        active_rows = conn.execute(
            "SELECT * FROM alerts WHERE status NOT IN ('closed','escalated')"
        ).fetchall()
        active_alerts = [_row_to_alert(row) for row in active_rows]
        overdue = sum(1 for item in active_alerts if item.get("sla", {}).get("status") == "overdue")
        warning = sum(1 for item in active_alerts if item.get("sla", {}).get("status") == "warning")
    return {
        "total": total,
        "pending": pending,
        "unassigned": unassigned,
        "sla_overdue": overdue,
        "sla_warning": warning,
        "by_status": by_status,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_category": by_category,
    }


def get_operations_summary(days: int = 7) -> Dict[str, Any]:
    init_db()
    days = max(1, min(int(days or 7), 365))
    start_time = datetime.now(timezone.utc) - timedelta(days=days)
    with _conn() as conn:
        rows = [_row_to_alert(row) for row in conn.execute("SELECT * FROM alerts ORDER BY created_at DESC")]
        entity_rows = [dict(row) for row in conn.execute(
            """
            SELECT entity_type, value, count(DISTINCT alert_id) AS c
            FROM entities
            GROUP BY entity_type, value
            ORDER BY c DESC
            LIMIT 10
            """
        )]

    period_alerts = []
    closed_period = []
    escalated_period = []
    for item in rows:
        created_at = _parse_time(item.get("created_at"))
        updated_at = _parse_time(item.get("updated_at"))
        if created_at and created_at >= start_time:
            period_alerts.append(item)
        if item.get("status") == "closed" and updated_at and updated_at >= start_time:
            closed_period.append(item)
        if item.get("status") == "escalated" and updated_at and updated_at >= start_time:
            escalated_period.append(item)

    active_alerts = [item for item in rows if item.get("status") not in CLOSED_STATUSES]
    overdue_alerts = [item for item in active_alerts if item.get("sla", {}).get("status") == "overdue"]
    warning_alerts = [item for item in active_alerts if item.get("sla", {}).get("status") == "warning"]

    close_hours = []
    for item in closed_period:
        created_at = _parse_time(item.get("created_at"))
        updated_at = _parse_time(item.get("updated_at"))
        if created_at and updated_at:
            close_hours.append(round((updated_at - created_at).total_seconds() / 3600, 2))

    owner_map: Dict[str, Dict[str, Any]] = {}
    for item in active_alerts:
        owner = item.get("owner") or "未分派"
        bucket = owner_map.setdefault(owner, {"owner": owner, "active": 0, "overdue": 0, "critical_high": 0})
        bucket["active"] += 1
        if item.get("sla", {}).get("status") == "overdue":
            bucket["overdue"] += 1
        if item.get("severity") in {"critical", "high"}:
            bucket["critical_high"] += 1

    source_counter = Counter(item.get("source_system") or "未知" for item in period_alerts)
    category_counter = Counter(item.get("source_category") or "other" for item in period_alerts)
    conclusion_counter = Counter(item.get("conclusion_label") or "未定" for item in rows)
    daily: Dict[str, Dict[str, int]] = {}
    for offset in range(days - 1, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=offset)).date().isoformat()
        daily[day] = {"date": day, "created": 0, "closed": 0, "escalated": 0}
    for item in rows:
        created_at = _parse_time(item.get("created_at"))
        updated_at = _parse_time(item.get("updated_at"))
        if created_at and created_at >= start_time:
            day = created_at.date().isoformat()
            if day in daily:
                daily[day]["created"] += 1
        if updated_at and updated_at >= start_time and item.get("status") in {"closed", "escalated"}:
            day = updated_at.date().isoformat()
            if day in daily:
                daily[day][item["status"]] += 1

    return {
        "period_days": days,
        "generated_at": _now(),
        "summary": {
            "created": len(period_alerts),
            "closed": len(closed_period),
            "escalated": len(escalated_period),
            "active": len(active_alerts),
            "overdue": len(overdue_alerts),
            "warning": len(warning_alerts),
            "avg_close_hours": round(sum(close_hours) / len(close_hours), 2) if close_hours else 0,
        },
        "owner_workload": sorted(owner_map.values(), key=lambda item: (item["overdue"], item["active"]), reverse=True),
        "source_rank": [{"name": name, "count": count} for name, count in source_counter.most_common(8)],
        "category_rank": [{"name": name, "count": count} for name, count in category_counter.most_common(8)],
        "conclusion_rank": [{"name": name, "count": count} for name, count in conclusion_counter.most_common(8)],
        "top_entities": [
            {"entity_type": row["entity_type"], "value": row["value"], "count": row["c"]}
            for row in entity_rows
        ],
        "daily_trend": list(daily.values()),
    }


def _csv_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return '"' + text.replace('"', '""') + '"'


def export_operations_csv(days: int = 7) -> str:
    report = get_operations_summary(days)
    lines = [
        "section,name,value,value2,value3",
        f"summary,period_days,{report['period_days']}",
        f"summary,created,{report['summary']['created']}",
        f"summary,closed,{report['summary']['closed']}",
        f"summary,escalated,{report['summary']['escalated']}",
        f"summary,active,{report['summary']['active']}",
        f"summary,overdue,{report['summary']['overdue']}",
        f"summary,avg_close_hours,{report['summary']['avg_close_hours']}",
    ]
    for item in report["owner_workload"]:
        lines.append(",".join(["owner_workload", _csv_cell(item["owner"]), str(item["active"]), str(item["overdue"]), str(item["critical_high"])]))
    for item in report["source_rank"]:
        lines.append(",".join(["source_rank", _csv_cell(item["name"]), str(item["count"])]))
    for item in report["top_entities"]:
        lines.append(",".join(["top_entities", _csv_cell(item["entity_type"]), _csv_cell(item["value"]), str(item["count"])]))
    for item in report["daily_trend"]:
        lines.append(",".join(["daily_trend", item["date"], str(item["created"]), str(item["closed"]), str(item["escalated"])]))
    return "\ufeff" + "\n".join(lines) + "\n"


def export_alert(alert_id: str, fmt: str = "json") -> Optional[Any]:
    alert = get_alert(alert_id)
    if not alert:
        return None
    if fmt == "markdown":
        lines = [
            f"# {alert.get('title') or '告警研判报告'}",
            "",
            "## 基本信息",
            f"- ID: {alert['id']}",
            f"- 来源系统: {alert.get('source_system') or '-'}",
            f"- 类型: {alert.get('alert_type') or '-'}",
            f"- 严重等级: {alert.get('severity')}",
            f"- 状态: {alert.get('status_label')}",
            f"- 结论: {alert.get('conclusion_label') or '-'}",
            f"- 上报人: {alert.get('created_by') or '-'}",
            f"- 负责人: {alert.get('owner') or '-'}",
            f"- 告警时间: {alert.get('occurred_at') or '-'}",
            "",
            "## 描述",
            alert.get("description") or "-",
            "",
            "## 关闭信息",
            f"- 关闭原因: {alert.get('close_reason') or '-'}",
            f"- 关键依据: {alert.get('key_evidence') or '-'}",
            f"- 处置建议: {alert.get('handling_suggestion') or '-'}",
            "",
            "## 关键实体",
        ]
        for entity in alert.get("entities", []):
            lines.append(f"- {entity['entity_type']} / {entity.get('role')}: {entity['value']}")
        lines.extend(["", "## 研判记录"])
        for note in alert.get("notes", []):
            lines.append(f"- {note['created_at']} [{note['note_type']}] {note.get('author') or '-'}: {note['content']}")
        lines.extend(["", "## 分派记录"])
        for assignment in alert.get("assignments", []):
            lines.append(
                f"- {assignment['created_at']} {assignment.get('assigned_by') or '-'}: "
                f"{assignment.get('from_owner') or '未分派'} -> {assignment.get('to_owner') or '未分派'}"
            )
        lines.extend(["", "## 升级记录"])
        for escalation in alert.get("escalations", []):
            lines.append(
                f"- {escalation['created_at']} {escalation.get('escalated_by') or '-'} -> "
                f"{escalation.get('target_team') or '-'} [{escalation.get('severity') or '-'}]: "
                f"{escalation.get('reason') or '-'}"
            )
        lines.extend(["", "## 附件"])
        for att in alert.get("attachments", []):
            lines.append(f"- {att['original_name']} ({att['file_type']}, {att['size']} bytes)")
        return "\n".join(lines)
    return alert


def export_all() -> Dict[str, Any]:
    alerts = list_alerts({"limit": 10000})
    return {
        "export_time": _now(),
        "alerts": alerts,
        "alert_count": len(alerts),
        "stats": get_stats(),
    }


def list_audit(limit: int = 100) -> List[Dict[str, Any]]:
    init_db()
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (int(limit),)
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["before_data"] = _json_loads(item.get("before_data"), {})
        item["after_data"] = _json_loads(item.get("after_data"), {})
        items.append(item)
    return items


def clear_all() -> bool:
    """兼容旧接口：仅清空告警相关数据库记录，不删除文件。"""
    with _conn() as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM attachments WHERE alert_id IS NULL")
    _audit("clear_all", "analysis", "all")
    return True


def save_alert_from_json(raw: Dict[str, Any]):
    return create_alert(raw)


def save_alert_from_file(file_storage):
    filename = file_storage.filename or "alert.json"
    if Path(filename).suffix.lower() != ".json":
        return None, "仅支持 .json 文件"
    data = file_storage.read()
    if len(data) > MAX_ATTACHMENT_SIZE:
        return None, f"文件大小超过限制（最大 {MAX_ATTACHMENT_SIZE // 1024 // 1024} MB）"
    try:
        raw = json.loads(data)
    except json.JSONDecodeError as e:
        return None, f"JSON 解析失败: {str(e)}"

    alert = create_alert(raw)
    saved_name = _safe_filename(filename)
    dest = Path(_ensure_dirs("attachments")) / saved_name
    dest.write_bytes(data)
    rel_path = f"attachments/{saved_name}"
    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO attachments
            (id, alert_id, file_type, filename, original_name, rel_path, size, mime, description, uploaded_by, uploaded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _id("att_"),
                alert["id"],
                "json",
                saved_name,
                filename,
                rel_path,
                len(data),
                "application/json",
                "原始告警 JSON",
                DEFAULT_ACTOR,
                _now(),
            ),
        )
    return get_alert(alert["id"]), None


def resolve_file_path(filepath: str) -> Optional[Path]:
    root = Path(UPLOAD_BASE).resolve()
    candidate = (root / filepath).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


init_db()
