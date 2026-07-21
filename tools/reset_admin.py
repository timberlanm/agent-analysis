# -*- coding: utf-8 -*-
"""重置初始管理员口令（本地维护/找回脚本）。

场景：首次启动打印的一次性 admin 口令被错过、无法登录。
用法：先停止正在运行的应用（关闭 start.bat 窗口），再执行：
        python tools/reset_admin.py
脚本会把 admin 账号口令重置为一段新的随机口令并打印到本机控制台；
登录后系统会强制你修改口令。
"""
import os
import sys
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.services import auth_service as a  # noqa: E402


def main():
    a.init_auth()
    new_pw = secrets.token_urlsafe(12)
    row = a._get_user_row_by_username("admin")
    if row is None:
        # 无 admin：优先走首次引导；若因存在其他用户而不引导，则直接创建
        pw = a.bootstrap()
        if pw:
            new_pw = pw
        else:
            a.create_user("admin", new_pw, "系统管理员", ["admin"],
                          actor="reset-script", must_change=True)
        action = "已创建管理员账号"
    else:
        a.admin_reset_password(row["id"], new_pw, actor="reset-script")
        action = "已重置管理员口令"

    line = "=" * 46
    print("\n" + line)
    print(f"  {action}")
    print("  用户名：admin")
    print(f"  新口令：{new_pw}")
    print("  ↑ 请立即用它登录；系统会要求你首次登录后修改口令。")
    print(line + "\n")


if __name__ == "__main__":
    main()
