# Orthanc — Django control plane (CA / AAA / SSO). One image, TWO roles picked by
# the Quadlet's Exec=: the web app (gunicorn orthanc.wsgi) and the mTLS control
# listener (manage.py run_control). Secrets/CA/keys are NEVER baked — they are
# mounted at runtime (.env, /var/lib/orthanc/ca/pki, /etc/orthanc/entra). See
# Lab/mcp-containers/deploy/orthanc-*.container.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DJANGO_SETTINGS_MODULE=orthanc.settings

WORKDIR /app

# ca-certificates for outbound TLS (Entra JWKS / requests). psycopg-binary bundles
# libpq and cryptography ships wheels, so no build toolchain / libpq-dev needed.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code only — NOT .env, ca/pki, entra keys, venv, or the collected staticfiles
# (see .dockerignore). collectstatic output + CA material live on mounted host paths.
COPY manage.py ./
COPY orthanc/ ./orthanc/
COPY ca/ ./ca/
COPY enrollment/ ./enrollment/
COPY sso/ ./sso/
COPY console/ ./console/

# Match the host `orthanc` service account so the mounted 0600 secrets + CA dir
# line up (same trick as ringdown/turnstone).
RUN groupadd --system --gid 988 orthanc \
 && useradd  --system --uid 999 --gid 988 --home-dir /app --shell /usr/sbin/nologin orthanc

USER 999:988

# Default = web role; the control Quadlet overrides Exec=.
CMD ["gunicorn", "orthanc.wsgi:application", "--bind", "127.0.0.1:8099", "--workers", "3", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-"]
