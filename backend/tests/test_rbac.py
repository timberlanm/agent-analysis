"""RBAC 回归套件：登录门控 / 对象级越权 / 读范围 / 服务令牌 / 审计 / 无锁定 / 可配置权限。"""
import io
import re
import sqlite3

import backend.services.incident_service as isvc
from backend.services import auth_service


def _new_alert(client, title="告警", cat="edr"):
    r = client.post("/api/incident/alerts", json={"title": title, "source_category": cat})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["data"]["id"]


def test_health_reports_database_mode(rbac):
    response = rbac.anon().get("/health")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "healthy"
    assert payload["database"] == {"mode": "sqlite", "connected": True}


# ============ Phase 0：登录与权限门控 ============

def test_login_and_basic_gating(rbac):
    rbac.create_user("ana", ["analyst"])
    anon = rbac.anon()
    assert anon.get("/api/incident/alerts").status_code == 401
    assert anon.post("/api/auth/login", json={"username": "ana", "password": "bad"}).status_code == 401

    ana = rbac.login("ana")
    me = ana.get("/api/auth/me")
    assert me.status_code == 200
    perms = set(me.get_json()["data"]["permissions"])
    assert "alert.create" in perms and "data.clear" not in perms

    assert ana.get("/api/incident/alerts").status_code == 200
    # 无 CSRF 头的写 -> 403
    raw = ana.c.post("/api/incident/alerts", json={"title": "x"})
    assert raw.status_code == 403
    # 带 CSRF -> 200，actor 记为真实用户名
    aid = _new_alert(ana)
    assert isvc.get_alert(aid)["created_by"] == "ana"
    # 越权
    assert ana.post("/api/incident/clear").status_code == 403
    assert ana.get("/api/incident/audit").status_code == 403
    # 登出后失效
    assert ana.post("/api/auth/logout").status_code == 200
    assert ana.get("/api/incident/alerts").status_code == 401


def test_removed_field_recognition_endpoints_are_unavailable(rbac):
    rbac.create_user("ana", ["analyst"])
    analyst = rbac.login("ana")
    permissions = analyst.get("/api/auth/me").get_json()["data"]["permissions"]
    assert "ocr.run" not in permissions
    assert analyst.get("/api/incident/ocr/status").status_code == 404
    assert analyst.post("/api/incident/extract-fields", json={"text": "src_ip=10.0.0.1"}).status_code == 404
    assert analyst.post("/api/incident/alerts/missing/ocr").status_code == 404


def test_removed_recognition_permission_is_cleaned_on_upgrade(rbac):
    with isvc._conn() as conn:
        conn.execute(
            "INSERT INTO permissions (code, name, category) VALUES ('ocr.run', 'OCR/字段抽取', '告警')"
        )
        conn.execute(
            "INSERT INTO role_permissions (role_code, permission_code) VALUES ('analyst', 'ocr.run')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO auth_meta (key, value) VALUES ('permission_policy_version', '3')"
        )

    auth_service.init_auth()

    with isvc._conn() as conn:
        assert conn.execute("SELECT 1 FROM permissions WHERE code = 'ocr.run'").fetchone() is None
        assert conn.execute(
            "SELECT 1 FROM role_permissions WHERE permission_code = 'ocr.run'"
        ).fetchone() is None


def test_alert_number_is_unique_and_searchable(rbac):
    rbac.create_user("root", ["admin"])
    root = rbac.login("root")
    first_id = _new_alert(root, "第一条长标题告警")
    second_id = _new_alert(root, "第二条长标题告警")

    first = root.get(f"/api/incident/alerts/{first_id}").get_json()["data"]
    second = root.get(f"/api/incident/alerts/{second_id}").get_json()["data"]
    assert re.fullmatch(r"SOC-\d{8}-\d{6,}", first["alert_no"])
    assert re.fullmatch(r"SOC-\d{8}-\d{6,}", second["alert_no"])
    assert first["alert_no"] != second["alert_no"]

    exact = root.get(
        f"/api/incident/alerts?keyword={first['alert_no']}"
    ).get_json()["data"]["alerts"]
    assert [item["id"] for item in exact] == [first_id]

    suffix = first["alert_no"].rsplit("-", 1)[-1]
    partial = root.get(
        f"/api/incident/alerts?keyword={suffix}"
    ).get_json()["data"]["alerts"]
    assert first_id in {item["id"] for item in partial}


def test_assigned_responder_can_download_attachment(rbac):
    rbac.create_user("root", ["admin"])
    rbac.create_user("resp", ["responder"])
    rbac.create_user("other", ["responder"])
    root, resp, other = (
        rbac.login("root"),
        rbac.login("resp"),
        rbac.login("other"),
    )
    alert_id = _new_alert(root, "附件下载验证")
    upload = root.post(
        f"/api/incident/alerts/{alert_id}/attachments",
        data={"file": (io.BytesIO(b"forensic evidence\n"), "evidence.txt")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200, upload.get_json()
    attachment = upload.get_json()["data"]["attachments"][0]
    assert attachment["file_available"] is True

    assert root.put(
        f"/api/incident/alerts/{alert_id}/handlers",
        json={"names": ["resp"]},
    ).status_code == 200
    assert resp.get(attachment["url"]).data == b"forensic evidence\n"
    assert other.get(attachment["url"]).status_code == 403

    path = isvc.resolve_file_path(attachment["rel_path"])
    assert path is not None
    path.unlink()
    missing = resp.get(attachment["url"])
    assert missing.status_code == 404
    assert missing.get_json()["error"] == "文件不存在"


# ============ Phase 1：对象级越权收敛 ============

def test_object_scope_writes(rbac):
    rbac.create_user("root", ["admin"])   # 仅管理员对象级豁免
    rbac.create_user("repA", ["reporter"])
    rbac.create_user("repB", ["reporter"])
    root, a, b = rbac.login("root"), rbac.login("repA"), rbac.login("repB")

    aid = _new_alert(a, "A 上报的告警")
    # repB 不能改/删 A 上报的告警（对象级限制）
    assert b.put(f"/api/incident/alerts/{aid}", json={"title": "x"}).status_code == 403
    assert b.delete(f"/api/incident/alerts/{aid}").status_code == 403
    # repA 能改自己上报的
    assert a.put(f"/api/incident/alerts/{aid}", json={"title": "改自己的"}).status_code == 200
    # 管理员豁免对象级，可改任意告警
    assert root.put(f"/api/incident/alerts/{aid}", json={"title": "管理员改"}).status_code == 200


def test_analyst_scope(rbac):
    rbac.create_user("root", ["admin"])
    rbac.create_user("anaA", ["analyst"])
    rbac.create_user("anaB", ["analyst"])
    root, a, b = rbac.login("root"), rbac.login("anaA"), rbac.login("anaB")
    aid = _new_alert(root, "待分配")  # 无处理人
    # 研判人员能看到待分配（own+unassigned），可自行领取
    assert aid in {x["id"] for x in a.get("/api/incident/alerts").get_json()["data"]["alerts"]}
    # 未领取前不能改（对象级收敛，非本人经手）
    assert b.put(f"/api/incident/alerts/{aid}", json={"title": "x"}).status_code == 403
    # 未分派告警可指派给有效账号；接手人随后可研判/编辑
    assert a.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["anaB"]}).status_code == 200
    assert b.put(f"/api/incident/alerts/{aid}", json={"title": "B 接手研判"}).status_code == 200
    # 非当前处理人不能越权改派他人已经接手的告警
    assert a.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["anaA"]}).status_code == 403
    # 管理员清空处理人后，研判员可以自领并继续研判
    assert root.put(f"/api/incident/alerts/{aid}/handlers", json={"names": []}).status_code == 200
    assert a.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["anaA"]}).status_code == 200
    assert a.put(f"/api/incident/alerts/{aid}", json={"title": "研判中"}).status_code == 200
    assert a.post(f"/api/incident/alerts/{aid}/conclusion", json={"conclusion": "business"}).status_code == 200
    # 不存在或停用的账号不能被指派
    assert a.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["other"]}).status_code == 403


def test_responder_scope(rbac):
    rbac.create_user("lead", ["admin"])
    rbac.create_user("resp", ["responder"])
    lead, resp = rbac.login("lead"), rbac.login("resp")
    aid = _new_alert(lead, "待处置")
    # 未指派前：处置人无定性权限、且备注被拒
    assert resp.post(f"/api/incident/alerts/{aid}/conclusion", json={"conclusion": "incident"}).status_code == 403
    assert resp.post(f"/api/incident/alerts/{aid}/notes", json={"content": "x"}).status_code == 403
    # 指派为处理人后可备注
    assert lead.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["resp"]}).status_code == 200
    assert resp.post(f"/api/incident/alerts/{aid}/notes", json={"content": "处置中"}).status_code == 200


# ============ Phase 2：读范围收敛 ============

def test_read_scope(rbac):
    rbac.create_user("root", ["admin"])
    rbac.create_user("ana", ["analyst"])
    rbac.create_user("resp", ["responder"])
    rbac.create_user("rep", ["reporter"])
    root, ana, resp, rep = rbac.login("root"), rbac.login("ana"), rbac.login("resp"), rbac.login("rep")
    a1 = _new_alert(root, "已分派给处置人")     # root 建，随后指派 resp
    a2 = _new_alert(ana, "研判自建/待分配")     # ana 建（创建者=经手），无处理人
    root.put(f"/api/incident/alerts/{a1}/handlers", json={"names": ["resp"]})

    # 应急处置人：只看受指派（a1）
    resp_ids = [x["id"] for x in resp.get("/api/incident/alerts").get_json()["data"]["alerts"]]
    assert resp_ids == [a1]
    assert resp.get(f"/api/incident/alerts/{a1}").status_code == 200
    assert resp.get(f"/api/incident/alerts/{a2}").status_code == 403
    for sub in ["notes", "entities", "attachments", "subtasks", "related", "correlation"]:
        assert resp.get(f"/api/incident/alerts/{a2}/{sub}").status_code == 403

    # 研判人员：只看本人经手（a2 自建），看不到别人经手的 a1
    ana_ids = {x["id"] for x in ana.get("/api/incident/alerts").get_json()["data"]["alerts"]}
    assert a2 in ana_ids and a1 not in ana_ids

    # 上报人：本人经手 + 待分配；a1 已有处理人(resp)且非本人→不可见，a2 待分配→可见
    rep_ids = {x["id"] for x in rep.get("/api/incident/alerts").get_json()["data"]["alerts"]}
    assert a2 in rep_ids and a1 not in rep_ids

    # 管理员：看全部
    root_ids = {x["id"] for x in root.get("/api/incident/alerts").get_json()["data"]["alerts"]}
    assert {a1, a2} <= root_ids


# ============ Phase 1：服务令牌 ============

def test_api_tokens(rbac):
    rbac.create_user("root", ["admin"])
    root = rbac.login("root")
    # 非法 scope 被拒
    assert root.post("/api/auth/tokens", json={"name": "bad", "scopes": ["data.clear"]}).status_code == 400
    tok = root.post("/api/auth/tokens", json={"name": "siem", "scopes": ["alert.create", "alert.view"]}).get_json()["data"]["token"]
    assert tok.startswith("svc_")

    svc = rbac.anon()
    bh = {"Authorization": f"Bearer {tok}"}
    r = svc.post("/api/incident/alerts", json={"title": "推送", "source_category": "siem"}, headers=bh)
    assert r.status_code == 200  # 免 CSRF
    assert r.get_json()["data"]["created_by"] == "svc:siem"
    assert svc.post("/api/incident/clear", headers=bh).status_code == 403  # 越权
    # 吊销后失效
    tid = root.get("/api/auth/tokens").get_json()["data"]["tokens"][0]["id"]
    assert root.delete(f"/api/auth/tokens/{tid}").status_code == 200
    assert svc.post("/api/incident/alerts", json={"title": "x"}, headers=bh).status_code == 401


# ============ Phase 3：审计强化 ============

def test_audit_hardening(rbac):
    rbac.create_user("root", ["admin"])
    rbac.create_user("ana", ["analyst"])
    root, ana = rbac.login("root"), rbac.login("ana")
    _new_alert(ana, "审计对象")
    ana.post("/api/incident/clear")  # 触发 permission_denied

    ana_uid = auth_service._get_user_row_by_username("ana")["id"]
    creates = [x for x in isvc.list_audit(500) if x["action"] == "create_alert" and x["actor"] == "ana"]
    assert creates and creates[0]["actor_user_id"] == ana_uid

    denied = root.get("/api/incident/audit?action=permission_denied").get_json()["data"]["items"]
    assert any(d["actor"] == "ana" and d["target_id"] == "data.clear" for d in denied)

    v = root.get("/api/incident/audit/verify").get_json()["data"]
    assert v["ok"] is True and v["checked"] > 0

    # 篡改 -> 断链
    conn = sqlite3.connect(isvc.DB_PATH)
    conn.execute("UPDATE audit_logs SET actor='HACK' WHERE id=(SELECT id FROM audit_logs ORDER BY rowid ASC LIMIT 1 OFFSET 2)")
    conn.commit(); conn.close()
    v2 = isvc.verify_audit_chain()
    assert v2["ok"] is False and v2["broken_at"]


# ============ Phase 4：登录失败锁定 ============

def test_login_lockout(rbac):
    """连续失败达到阈值后账号被临时锁定，正确口令也无法登录；
    锁定不改账号 status（管理员重置口令/启用账号时自动清零）。"""
    rbac.create_user("u1", ["analyst"])
    pw = "Passw0rd!2026"

    # 阈值前 7 次失败：返回「用户名或口令错误」
    for _ in range(auth_service.LOGIN_FAILURE_THRESHOLD - 1):
        r = rbac.anon().post("/api/auth/login", json={"username": "u1", "password": "wrong"})
        assert r.status_code == 401
        assert "锁定" not in r.get_json().get("error", "")

    # 第 8 次失败：触发锁定，返回锁定提示
    r = rbac.anon().post("/api/auth/login", json={"username": "u1", "password": "wrong"})
    assert r.status_code == 401
    assert "锁定" in r.get_json()["error"]

    # 锁定后正确口令也无法登录
    r = rbac.anon().post("/api/auth/login", json={"username": "u1", "password": pw})
    assert r.status_code == 401
    assert "锁定" in r.get_json()["error"]

    # 账号 status 仍为 active（临时锁定不改状态）
    row = auth_service._get_user_row_by_username("u1")
    assert row["status"] == "active"
    assert row["failed_login_count"] >= auth_service.LOGIN_FAILURE_THRESHOLD
    assert row["locked_until"] is not None

    # 管理员重置口令/启用账号时自动清零（模拟 admin_reset_password 的清零效果）
    import sqlite3
    conn = sqlite3.connect(isvc.DB_PATH)
    conn.execute(
        "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = 'u1'"
    )
    conn.commit()
    conn.close()

    # 清零后可正常登录
    assert rbac.login("u1")
    row = auth_service._get_user_row_by_username("u1")
    assert row["failed_login_count"] == 0
    assert row["locked_until"] is None


# ============ Phase 5：可配置权限 ============

def test_configurable_permissions(rbac):
    rbac.create_user("root", ["admin"])
    rbac.create_user("v", ["liaison"])
    root = rbac.login("root")

    # 默认：liaison 无导出权限
    v = rbac.login("v")
    assert v.get("/api/incident/alerts").status_code == 200
    assert v.get("/api/incident/export").status_code == 403

    # 管理员给 liaison 赋 export 权限
    r = root.put("/api/auth/roles/liaison/permissions", json={"permissions": ["alert.view", "export"]})
    assert r.status_code == 200
    # 该 liaison 重新登录后即拥有 export
    v2 = rbac.login("v")
    assert v2.get("/api/incident/export").status_code == 200

    # 收回 export
    root.put("/api/auth/roles/liaison/permissions", json={"permissions": ["alert.view"]})
    assert rbac.login("v").get("/api/incident/export").status_code == 403

    # admin 角色不可改
    assert root.put("/api/auth/roles/admin/permissions", json={"permissions": ["alert.view"]}).status_code == 400
    # admin 始终拥有全部权限
    matrix = root.get("/api/auth/permissions").get_json()["data"]["matrix"]
    assert set(matrix["admin"]) == set(auth_service.ALL_PERMISSIONS)


# ============ Phase 6：H1 回归 - 双角色执行人不可升级到全字段编辑 ============

def _new_subtask(client, alert_id, assignee, title="子任务"):
    r = client.post(f"/api/incident/alerts/{alert_id}/subtasks",
                    json={"title": title, "assignee": assignee, "team": "应急组"})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["data"]["id"]


def test_h1_dualrole_assignee_cannot_escalate(rbac):
    """双角色(responder+analyst)用户作为子任务执行人时，只能改 status，
    不能因同时持有 subtask.manage 而升级到全字段编辑（H1 垂直越权）。"""
    rbac.create_user("root", ["admin"])
    rbac.create_user("ana", ["analyst"])
    # 双角色用户：同时持有 subtask.manage（来自 analyst）和 subtask.execute（来自 responder）
    rbac.create_user("dual", ["responder", "analyst"])
    root, ana, dual = rbac.login("root"), rbac.login("ana"), rbac.login("dual")

    # ana 创建告警；用 admin 建立固定的双处理人测试前置状态
    aid = _new_alert(ana, "H1回归告警")
    assert root.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["ana", "dual"]}).status_code == 200
    # ana 创建子任务，指派给 dual（dual 成为该子任务执行人）
    sid = _new_subtask(ana, aid, assignee="dual", title="原始标题")

    # dual 作为执行人，尝试改 title -> 应被拒（即使持有 subtask.manage）
    r = dual.put(f"/api/incident/subtasks/{sid}", json={"title": "被篡改的标题"})
    assert r.status_code == 403, f"执行人不应能改 title, got {r.status_code}"
    # 改 due_at -> 应被拒
    r = dual.put(f"/api/incident/subtasks/{sid}", json={"due_at": "2099-12-31T23:59:59"})
    assert r.status_code == 403, f"执行人不应能改 due_at, got {r.status_code}"
    # 改 assignee（甩锅）-> 应被拒
    r = dual.put(f"/api/incident/subtasks/{sid}", json={"assignee": "ana"})
    assert r.status_code == 403, f"执行人不应能改 assignee, got {r.status_code}"
    # 改 status -> 应成功（执行人本职能力）
    r = dual.put(f"/api/incident/subtasks/{sid}", json={"status": "doing"})
    assert r.status_code == 200, f"执行人应能改 status, got {r.status_code}: {r.get_json()}"

    # 验证 title 未被篡改
    subs = ana.get(f"/api/incident/alerts/{aid}/subtasks").get_json()["data"]["subtasks"]
    target = next(s for s in subs if s["id"] == sid)
    assert target["title"] == "原始标题", f"title 被篡改为 {target['title']!r}"
    assert target["status"] == "doing"


def test_h1_non_assignee_with_manage_can_edit(rbac):
    """持有 subtask.manage 但不是该子任务执行人的用户（如研判员），仍可全字段编辑。
    确保修复未误伤管理员/研判员的正常子任务管理能力。"""
    rbac.create_user("root", ["admin"])
    rbac.create_user("ana", ["analyst"])
    rbac.create_user("resp", ["responder"])
    root, ana, resp = rbac.login("root"), rbac.login("ana"), rbac.login("resp")

    aid = _new_alert(ana, "正常管理告警")
    ana.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["ana"]})
    sid = _new_subtask(ana, aid, assignee="resp", title="待处置")

    # ana 是 handler 且持有 subtask.manage，但不是该子任务执行人 -> 可改 title
    r = ana.put(f"/api/incident/subtasks/{sid}", json={"title": "研判员改的标题"})
    assert r.status_code == 200, f"研判员应能管理子任务, got {r.status_code}: {r.get_json()}"
    # resp 是执行人，只能改 status
    r = resp.put(f"/api/incident/subtasks/{sid}", json={"title": "处置人改的"})
    assert r.status_code == 403
