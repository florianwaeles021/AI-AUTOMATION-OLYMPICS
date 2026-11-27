"""Configuration is read from the environment; no secrets live in source control."""
import os

SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
DEBUG = os.environ.get("FLASK_DEBUG") == "1"
HOST = os.environ.get("APP_HOST", "127.0.0.1")
# Hosts /fetch may contact (comma separated). Empty = feature disabled.
FETCH_ALLOWED_HOSTS = {h for h in os.environ.get("FETCH_ALLOWED_HOSTS", "").split(",") if h}
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
