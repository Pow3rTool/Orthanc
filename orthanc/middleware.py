"""Security-header middleware: sets a Content-Security-Policy on every response.

Defense-in-depth — the console has no known XSS surface (Django autoescape is on,
no |safe/mark_safe), but a CSP still blocks external resource loads, clickjacking
(frame-ancestors), and base-tag / form-action hijacking. The console templates use
inline <style>/<script>, so those need 'unsafe-inline'; everything else is locked
to 'self'. Override the whole policy via ORTHANC_CSP if templates change.
"""
from django.conf import settings

_DEFAULT_CSP = (
    "default-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class ContentSecurityPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.csp = getattr(settings, "CONTENT_SECURITY_POLICY", "") or _DEFAULT_CSP

    def __call__(self, request):
        resp = self.get_response(request)
        resp.setdefault("Content-Security-Policy", self.csp)
        return resp
