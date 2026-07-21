# -*- coding: utf-8 -*-
"""批量创建账号（本地管理员维护脚本）。

把当前告警数据里出现的「上报人 / 处理人」建成系统账号：
- 用户名与现有名字一致（这样现有告警里的指派/上报能对应到真实账号）；
- 统一角色 analyst（研判员），可在「账号管理」里再逐个调整；
- 每人随机初始口令、首次登录强制改密；
- 口令写入项目根目录的凭据清单文件（不打印到控制台），分发后请删除。

用法（建议先停止正在运行的应用，避免数据库占用）：
    python tools/batch_create_users.py
可重复运行：已存在的账号会自动跳过。
"""
import os
import sys
import secrets

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from backend.services import auth_service as a  # noqa: E402

# 用户名列表（与数据中的名字一致）；排除测试垃圾 dda/ddddd/ggg/tester
USERS = [
    "soc_chenhao", "soc_zhangwei", "soc_liyang",
    "ir_lina", "ir_zhao",
    "张三", "王工", "潘工", "林工", "马工", "丰工",
    "appsec_team", "cloud_team", "ops_admin",
]
ROLE = "analyst"
CRED_FILE = os.path.join(ROOT, "初始账号口令_请分发后删除.txt")


def main():
    a.init_auth()
    created, skipped, creds = [], [], []
    for uname in USERS:
        if a._get_user_row_by_username(uname):
            skipped.append(uname)
            continue
        pw = secrets.token_urlsafe(9)  # 约 12 位，满足最小长度
        try:
            a.create_user(uname, pw, uname, [ROLE], actor="admin-batch", must_change=True)
            created.append(uname)
            creds.append((uname, pw))
        except Exception as e:  # noqa: BLE001
            skipped.append(f"{uname}(失败:{e})")

    if creds:
        with open(CRED_FILE, "w", encoding="utf-8") as f:
            f.write("初始账号口令清单\n")
            f.write("角色：研判员(analyst)；首次登录强制改密。分发后请删除本文件。\n")
            f.write("=" * 52 + "\n")
            for u, p in creds:
                f.write(f"用户名：{u}\t初始口令：{p}\n")

    # 只报告用户名与结果，不打印任何口令
    print(f"新建：{len(created)} 个 -> {created}")
    print(f"跳过：{len(skipped)} 个 -> {skipped}")
    if creds:
        print(f"初始口令已写入：{CRED_FILE}")
    else:
        print("无新建账号（可能都已存在）。")


if __name__ == "__main__":
    main()
