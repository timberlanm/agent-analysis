"""pytest 夹具：每个测试一套全新的临时库，绝不触碰仓库内真实库。

关键：在导入任何 backend 模块前先设好 INCIDENT_DB_PATH，
使 incident_service 在 import 时的 init_db() 也落到临时库。
"""
import os
import sys
import tempfile
from pathlib import Path

# 项目根入 sys.path
_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

# import 期就把库指向临时目录（collection 阶段的 init_db 也不碰真实库）
os.environ.setdefault("INCIDENT_DB_PATH", str(Path(tempfile.mkdtemp()) / "collect.db"))

import pytest  # noqa: E402
import backend.services.incident_service as isvc  # noqa: E402
from backend.services import auth_service  # noqa: E402


def _csrf(resp):
    for k, v in resp.headers:
        if k.lower() == "set-cookie" and v.startswith("csrf_token="):
            return v.split(";")[0].split("=", 1)[1]
    return ""


class AuthClient:
    """包一层 test_client：自动带 CSRF 头、直接返回解析后的响应。"""

    def __init__(self, client, csrf):
        self.c = client
        self.csrf = csrf

    def _h(self, extra=None):
        h = {"X-CSRF-Token": self.csrf}
        if extra:
            h.update(extra)
        return h

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, **kw):
        return self.c.post(url, headers=self._h(kw.pop("headers", None)), **kw)

    def put(self, url, **kw):
        return self.c.put(url, headers=self._h(kw.pop("headers", None)), **kw)

    def delete(self, url, **kw):
        return self.c.delete(url, headers=self._h(kw.pop("headers", None)), **kw)


class RBAC:
    def __init__(self, app):
        self.app = app

    def create_user(self, username, roles, pw="Passw0rd!23"):
        auth_service.create_user(username, pw, username, roles, actor="system", must_change=False)
        return pw

    def login(self, username, pw="Passw0rd!23"):
        c = self.app.test_client()
        r = c.post("/api/auth/login", json={"username": username, "password": pw})
        assert r.status_code == 200, r.get_json()
        return AuthClient(c, _csrf(r))

    def anon(self):
        return self.app.test_client()


@pytest.fixture
def rbac():
    """全新临时库 + 全新 app（含引导 admin）。"""
    db_dir = tempfile.mkdtemp()
    isvc.DB_PATH = Path(db_dir) / "test.db"
    isvc.init_db()
    auth_service.init_auth()
    from backend.app import create_app
    app = create_app(serve_frontend=False)
    return RBAC(app)
