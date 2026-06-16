"""
Incident Analysis Backend
Flask 主应用入口 — 同时托管 API 和前端静态文件

启动方式：
  python backend/app.py                      # 仅 API
  python backend/app.py --serve-frontend     # API + 前端（生产模式，单端口）
"""
import sys
import os

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from backend.config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, API_PREFIX
from backend.api.incident import incident_bp

# 前端构建产物目录（执行过 npm run build 后生成）
_FRONTEND_DIST = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'frontend', 'dist')
)

# 前端开发源码目录（用于开发模式直接托管 index.html）
_FRONTEND_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'frontend')
)


def create_app(serve_frontend=False):
    """创建并配置 Flask 应用"""
    app = Flask(
        __name__,
        static_folder=_FRONTEND_DIST if serve_frontend else None,
        static_url_path='' if serve_frontend else None
    )
    # Allow forensic uploads through Flask; incident_service applies stricter
    # per-type limits for images, logs, compressed logs, and packet captures.
    app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024

    # CORS：生产/同源部署时不需要，但保留以支持开发模式直连
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Accept", "Cache-Control"],
        }
    })

    # 注册 API 蓝图（仅 Incident）
    app.register_blueprint(incident_bp, url_prefix=f'{API_PREFIX}/incident')

    # 健康检查
    @app.route('/health')
    def health():
        return jsonify({
            "status": "healthy",
            "service": "incident-analysis-backend"
        })

    # API 根路径
    @app.route(f'{API_PREFIX}')
    def api_root():
        return jsonify({
            "service": "Incident Analysis API",
            "version": "1.0.0"
        })

    # ---- 前端静态文件托管（生产模式 / 混合开发模式） ----
    if serve_frontend:
        _setup_frontend_routes(app)

    # 错误处理
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"success": False, "error": "Endpoint not found"}), 404

    @app.errorhandler(413)
    def request_too_large(error):
        return jsonify({"success": False, "error": "上传文件过大，请控制在 500 MB 以内"}), 413

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"success": False, "error": "Internal server error"}), 500

    return app


def _setup_frontend_routes(app):
    """为 Flask 注册前端 SPA 静态文件路由。
    优先使用构建产物 (frontend/dist)，不存在时使用开发目录 (frontend/)。
    """
    dist_exists = os.path.isdir(_FRONTEND_DIST)
    serve_dir = _FRONTEND_DIST if dist_exists else _FRONTEND_SRC
    mode_label = '生产构建 (dist)' if dist_exists else '开发源码 (src)'

    index_path = os.path.join(serve_dir, 'index.html')
    if not os.path.isfile(index_path):
        print(f"  [WARN] index.html not found: {index_path}")
        return

    # 注册 Vue Router 顶层路径（仅 / 和 /incident）
    for route in ['/', '/incident']:
        app.add_url_rule(route, f'_spa_{route.strip("/") or "home"}',
                         lambda: send_from_directory(serve_dir, 'index.html'))

    # 静态资源 assets/
    @app.route('/assets/<path:filename>')
    def spa_assets(filename):
        return send_from_directory(os.path.join(serve_dir, 'assets'), filename)

    # 兜底 catch-all
    @app.route('/<path:_spa_path>')
    def spa_fallback(_spa_path):
        return send_from_directory(serve_dir, 'index.html')

    print(f"  前端托管: {mode_label} ← {serve_dir}")


def main():
    """主函数"""
    _has_frontend = (
        os.path.isfile(os.path.join(_FRONTEND_DIST, 'index.html')) or
        os.path.isfile(os.path.join(_FRONTEND_SRC, 'index.html'))
    )
    serve_frontend = '--serve-frontend' in sys.argv or _has_frontend

    app = create_app(serve_frontend=serve_frontend)

    print(f"\n{'='*50}")
    print(f"  Incident Analysis Backend")
    print(f"  http://{FLASK_HOST}:{FLASK_PORT}")
    print(f"  API: {API_PREFIX}")
    if serve_frontend:
        print(f"  前端: http://{FLASK_HOST}:{FLASK_PORT}")
    print(f"{'='*50}\n")

    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG,
        threaded=True,
        use_reloader=False
    )


if __name__ == '__main__':
    main()
