"""RBAC 回归套件：登录门控 / 对象级越权 / 读范围 / 服务令牌 / 审计 / 无锁定 / 可配置权限。"""
import sqlite3

import backend.services.incident_service as isvc
from backend.services import auth_service


def _new_alert(client, title="告警", cat="edr"):
    r = client.post("/api/incident/alerts", json={"title": title, "source_category": cat})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["data"]["id"]


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
    # 自领（assign=self）后可研判/编辑
    assert a.put(f"/api/incident/alerts/{aid}/handlers", json={"names": ["anaA"]}).status_code == 200
    assert a.put(f"/api/incident/alerts/{aid}", json={"title": "研判中"}).status_code == 200
    assert a.post(f"/api/incident/alerts/{aid}/conclusion", json={"conclusion": "business"}).status_code == 200
    # 不能改派他人
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


# ============ Phase 4：不启用失败锁定 ============

def test_no_lockout(rbac):
    rbac.create_user("u1", ["analyst"])
    for _ in range(8):
        assert rbac.anon().post("/api/auth/login", json={"username": "u1", "password": "wrong"}).status_code == 401
    # 仍可正常登录
    assert rbac.login("u1")
    assert auth_service._get_user_row_by_username("u1")["status"] == "active"


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
