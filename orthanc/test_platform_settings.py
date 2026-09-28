"""Isolated PostgreSQL integration tests: never import deployment .env or CA keys.

Usage: DJANGO_SETTINGS_MODULE=orthanc.test_platform_settings python manage.py test enrollment.tests_platform
Start a disposable PostgreSQL instance on 127.0.0.1:55439 first.
"""
import os
import tempfile
import atexit
from pathlib import Path

SECRET_KEY = "isolated-platform-tests-only"
DEBUG = True
ALLOWED_HOSTS = ["testserver", "localhost"]
INSTALLED_APPS = [
    "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
    "django.contrib.messages", "django.contrib.staticfiles", "django.contrib.humanize",
    "ca", "enrollment", "sso", "console",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "orthanc.middleware.ContentSecurityPolicyMiddleware",
]
ROOT_URLCONF = "orthanc.urls"
ENABLE_DJANGO_ADMIN = False
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True, "OPTIONS": {"context_processors": []},
}]
DATABASES = {"default": {
    "ENGINE": "django.db.backends.postgresql",
    "NAME": "rcon_platform_test", "USER": "postgres",
    "PASSWORD": "isolated-test-only",
    "TEST": {"CHARSET": "UTF8", "TEMPLATE": "template0"},
    "HOST": "127.0.0.1", "PORT": os.environ.get("RCON_TEST_DB_PORT", "55439"),
}}
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
STATIC_URL = "/static/"
SPIFFE_TRUST_DOMAIN = "pow3rtool"
BOOTSTRAP_URL = "https://lab.example"

# Never use deployment key material, including during enrollment tests.
_test_ca = tempfile.TemporaryDirectory(prefix="orthanc-test-ca-")
atexit.register(_test_ca.cleanup)
CA_DIR = Path(_test_ca.name)
NODE_CERT_TTL_HOURS = 24
JOIN_TOKEN_TTL_MINUTES = 60
SSO_ROLE_CLAIMS = {
    "orthanc.admin": "admin", "orthanc.approver": "approver", "orthanc.viewer": "viewer",
}
LOGIN_URL = "/oidc/login"
OBO_VALIDATE_TOKEN = False  # synthetic principals in unit tests only
