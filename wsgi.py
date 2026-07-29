"""WSGI entry point for Linux application servers such as Gunicorn."""

from backend.app import create_app


app = create_app(serve_frontend=True)
