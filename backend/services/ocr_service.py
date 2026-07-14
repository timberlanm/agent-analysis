"""
截图 OCR → 文本 → IOC 字段 提取。

设计要点：
- OCR 引擎可插拔、懒加载、按优先级自动探测（RapidOCR → PaddleOCR → pytesseract）；
  未安装任何引擎时**优雅降级**——抛出带安装指引的可读错误，前端提示，不影响其余功能。
- 文本 → 字段 分两段：
    ① 逐行「标签: 值」解析（对告警面板类截图效果最好，能区分源/目的 IP 等）；
    ② 复用 incident_service 的正则实体抽取兜底 IP/Hash/URL/域名/路径。
- 产出字段仅作**预填**，标记「待确认」，由研判员核对/订正后再写入告警详情。
- 引擎装好后本地离线运行，不依赖大模型、不联网。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import incident_service as inc

# ------------------------------------------------------------------
# OCR 引擎（懒加载单例，按优先级探测）
# ------------------------------------------------------------------
_engine: Any = None
_engine_name: Optional[str] = None
_engine_error: Optional[str] = None
_loaded = False

_INSTALL_HINT = (
    "未检测到可用的 OCR 引擎，无法从截图识别字段。请在后端环境任选其一安装"
    "（本地离线、无需大模型）：\n"
    "  1) pip install rapidocr-onnxruntime   （推荐：模型随包、支持中英文、CPU 运行）\n"
    "  2) pip install paddlepaddle paddleocr\n"
    "  3) pip install pytesseract 并额外安装 Tesseract-OCR 程序（含 chi_sim 语言包）\n"
    "安装后重启后端即可生效。"
)


def _load_engine() -> None:
    global _engine, _engine_name, _engine_error, _loaded
    if _loaded:
        return
    _loaded = True

    # 1) RapidOCR（ONNX，离线，中英文，模型随包）
    try:
        from rapidocr_onnxruntime import RapidOCR

        _engine = RapidOCR()
        _engine_name = "rapidocr"
        return
    except Exception:
        pass

    # 2) PaddleOCR
    try:
        from paddleocr import PaddleOCR

        _engine = PaddleOCR(use_angle_cls=True, lang="ch", show_log=False)
        _engine_name = "paddleocr"
        return
    except Exception:
        pass

    # 3) pytesseract（需系统安装 Tesseract-OCR）
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401

        _engine = "pytesseract"
        _engine_name = "pytesseract"
        return
    except Exception:
        pass

    _engine_error = _INSTALL_HINT


def engine_status() -> Dict[str, Any]:
    """供前端探测 OCR 能力是否就绪。"""
    _load_engine()
    return {
        "available": _engine is not None,
        "engine": _engine_name,
        "hint": None if _engine is not None else _engine_error,
    }


def image_to_text(path: str) -> str:
    """对单张图片做 OCR，返回按行拼接的纯文本。"""
    _load_engine()
    if _engine is None:
        raise RuntimeError(_engine_error or _INSTALL_HINT)

    if _engine_name == "rapidocr":
        result, _elapse = _engine(path)
        if not result:
            return ""
        # result: [[box, text, score], ...]
        return "\n".join(str(item[1]) for item in result)

    if _engine_name == "paddleocr":
        pages = _engine.ocr(path, cls=True) or []
        lines: List[str] = []
        for page in pages:
            for item in (page or []):
                try:
                    lines.append(str(item[1][0]))
                except Exception:
                    continue
        return "\n".join(lines)

    if _engine_name == "pytesseract":
        import pytesseract
        from PIL import Image

        return pytesseract.image_to_string(Image.open(path), lang="chi_sim+eng")

    return ""


# ------------------------------------------------------------------
# 文本 → 字段
# ------------------------------------------------------------------
# 归一化字段 → 标签别名（中英文）。用于「标签: 值」逐行解析；
# 别名在匹配前会去掉全部空白并转小写，故无需列出带空格/不带空格的两份。
FIELD_LABEL_ALIASES: Dict[str, List[str]] = {
    "source_ip": ["源ip", "来源ip", "攻击ip", "源地址", "sourceip", "srcip", "sip", "客户端ip", "客户端地址"],
    "destination_ip": ["目的ip", "目标ip", "被攻击ip", "目的地址", "destinationip", "dstip", "dip", "服务器ip"],
    "source_port": ["源端口", "sourceport", "srcport", "sport"],
    "destination_port": ["目的端口", "目标端口", "destinationport", "dstport", "dport"],
    "hostname": ["主机名", "主机", "hostname", "host", "资产名", "资产名称", "计算机名", "设备名"],
    "username": ["用户名", "用户", "账号", "账户", "username", "user", "account", "登录用户"],
    "domain": ["域名", "domain", "dns", "fqdn", "请求域名", "外联域名", "恶意域名", "c2域名", "访问域名"],
    "url": ["url", "uri", "网址", "请求地址", "请求url", "访问地址"],
    "file_hash": ["文件hash", "文件哈希", "哈希", "哈希值", "hash", "sha256", "sha-256", "sha1", "sha-1", "md5"],
    "file_path": ["文件路径", "路径", "filepath", "path", "镜像路径", "程序路径"],
    "process_name": ["进程名", "进程", "进程名称", "process", "processname", "image", "映像名称"],
    "command_line": ["命令行", "命令", "cmd", "cmdline", "commandline", "执行命令"],
    "rule_name": ["规则名称", "规则", "规则名", "rule", "rulename", "signature", "检测名称", "告警名称", "威胁名称"],
    "rule_id": ["规则id", "规则编号", "ruleid", "signatureid", "eventid"],
    "protocol": ["协议", "protocol", "传输协议", "网络协议"],
    "http_method": ["http方法", "请求方法", "method", "httpmethod"],
    "http_status": ["响应状态", "状态码", "响应码", "statuscode", "responsecode", "httpstatus"],
    "user_agent": ["useragent", "ua"],
    "event_action": ["检测动作", "动作", "处置动作", "action", "eventaction", "操作"],
}

# 这些字段的值常被 OCR 插入空白（如长 Hash / IP），写入前去掉内部空白。
_COMPACT_KEYS = {"source_ip", "destination_ip", "source_port", "destination_port", "file_hash"}

# 反向索引：去空白小写别名 → 字段 key
_LABEL_INDEX: Dict[str, str] = {
    re.sub(r"\s+", "", alias.lower()): key
    for key, aliases in FIELD_LABEL_ALIASES.items()
    for alias in aliases
}

# 「标签<分隔符>值」：优先中英文冒号/等号；否则「标签<空白>值」（标签需命中别名才采用）
_KV_COLON = re.compile(r"^\s*([^：:=]{1,40}?)\s*[：:=]\s*(.+)$")
_KV_SPACE = re.compile(r"^\s*(\S{1,20})\s+(.+)$")

# 这些「TLD」其实是文件扩展名，用于把 powershell.exe / a.ps1 之类从「域名」误判里剔除
_FILE_EXT_TLDS = {
    "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "jar", "py", "sh", "dat", "bin",
    "tmp", "log", "txt", "png", "jpg", "jpeg", "gif", "bmp", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "zip", "rar", "7z", "gz", "msi", "sys", "scr",
    "lnk", "conf", "ini", "cfg", "json", "xml", "yml", "yaml", "html", "htm", "css",
}


def _match_field_key(label: str) -> Optional[str]:
    return _LABEL_INDEX.get(re.sub(r"\s+", "", label.strip().lower()))


def _split_label_value(line: str):
    m = _KV_COLON.match(line)
    if m:
        return m.group(1), m.group(2)
    m = _KV_SPACE.match(line)
    if m:
        return m.group(1), m.group(2)
    return None, None


def _looks_like_domain(value: str) -> bool:
    v = value.strip().rstrip(".")
    if "." not in v:
        return False
    return v.rsplit(".", 1)[-1].lower() not in _FILE_EXT_TLDS


def _clean_value(key: str, value: str) -> str:
    v = value.strip().strip("。，,；;、")
    if key in _COMPACT_KEYS:
        v = re.sub(r"\s+", "", v)
    return v.strip()


def parse_fields_from_text(text: str) -> Dict[str, str]:
    """从 OCR 文本中提取归一化字段（key → value）。"""
    fields: Dict[str, str] = {}

    # ① 逐行「标签<分隔符>值」解析（对结构化告警文本/面板截图效果最好，能区分源/目的 IP）
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        label, value = _split_label_value(line)
        if not label:
            continue
        key = _match_field_key(label)
        if key and key not in fields:
            cleaned = _clean_value(key, value)
            if cleaned:
                fields[key] = cleaned

    # ② 正则实体兜底（只补 ① 未覆盖到的），复用 incident_service 的模式
    by_type: Dict[str, List[str]] = {}
    for ent in inc.extract_entities(text or ""):
        by_type.setdefault(ent.get("entity_type"), []).append(str(ent.get("value")))
    # 剔除把文件名（powershell.exe / a.ps1）误当域名的候选
    by_type["domain"] = [d for d in by_type.get("domain", []) if _looks_like_domain(d)]

    def _fill(key: str, entity_type: str, index: int = 0) -> None:
        values = by_type.get(entity_type, [])
        if key not in fields and len(values) > index:
            fields[key] = _clean_value(key, values[index])

    _fill("file_hash", "hash")
    _fill("url", "url")
    _fill("domain", "domain")
    _fill("file_path", "file_path")
    _fill("source_ip", "ip", 0)        # 首个 IP 猜作源 IP
    _fill("destination_ip", "ip", 1)   # 次个 IP 猜作目的 IP

    return fields


# ------------------------------------------------------------------
# 编排：对某告警的图片附件做识别
# ------------------------------------------------------------------
def extract_from_alert(alert_id: str) -> Dict[str, Any]:
    """
    对该告警的所有图片附件做 OCR，解析出候选字段。
    仅返回结果供前端预览/核对，不写库。
    """
    images = [a for a in inc.list_attachments(alert_id) if a.get("file_type") == "image"]
    if not images:
        raise ValueError("该告警没有可识别的图片附件，请先上传告警截图。")

    _load_engine()
    if _engine is None:
        raise RuntimeError(_engine_error or _INSTALL_HINT)

    texts: List[str] = []
    used: List[str] = []
    for att in images:
        path = inc.resolve_file_path(att.get("rel_path"))
        if not path or not path.is_file():
            continue
        text = image_to_text(str(path))
        if text:
            texts.append(text)
        used.append(att.get("original_name") or att.get("filename") or "")

    full_text = "\n".join(texts)
    return {
        "engine": _engine_name,
        "image_count": len(used),
        "images": used,
        "text": full_text,
        "fields": parse_fields_from_text(full_text),
    }
