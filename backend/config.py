"""
Incident Analysis Backend Configuration
"""
import os

# Flask configuration
FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
FLASK_PORT = int(os.environ.get('FLASK_PORT', 5000))
FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

# API prefix
API_PREFIX = '/api'

# ---- 认证 / 会话 / CORS ----
# 生产单端口(Flask 托管前端)为同源部署,CORS 用不到;下列 origin 仅供开发直连。
# 一旦启用 Cookie 会话,origins 不能再用 "*"(与 credentials 不兼容且不安全)。
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get(
        'ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000'
    ).split(',') if o.strip()
]
# 反代/网关启用 HTTPS 时置为 True,让会话 cookie 带 Secure 标记。
SECURE_COOKIE = os.environ.get('SECURE_COOKIE', 'False').lower() == 'true'
# 同源部署用 Lax 即可抵御 CSRF;跨站场景需另行评估。
COOKIE_SAMESITE = os.environ.get('COOKIE_SAMESITE', 'Lax')
