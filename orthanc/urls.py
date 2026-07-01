"""
URL configuration for orthanc project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # Operator SSO: /oidc/login, /oidc/callback, /oidc/logout, /oidc/me
    path('', include('sso.urls')),
    # Management console (SSO-gated): / dashboard, /tenant/<slug>
    path('', include('console.urls')),
    # NOTE: the public certless enrollment API (enrollment.urls: /<tenant>/register,
    # /<tenant>/enroll/<id>) is deliberately NOT routed. Enrollment is fronted by
    # XConnect (/bootstrap/*) and reaches Orthanc only over the mTLS control link
    # (/control/v1/sign + /control/v1/enroll_status). Exposing it here too would be a
    # second, unauthenticated (join-token-only) enrollment surface on the public
    # tower — violating the "nodes only ever talk to XConnect" invariant. The
    # register()/poll *services* remain (used by the control relay); only the public
    # HTTP route is removed. (scripts/enroll_client.py was the sole direct caller.)
]

# Django's password-auth /admin/ bypasses the Entra tier model — OFF by default
# (ORTHANC_ENABLE_DJANGO_ADMIN). Enable only for break-glass, proxy-restricted to
# localhost. Routed FIRST so it isn't shadowed by the catch-all includes above.
if settings.ENABLE_DJANGO_ADMIN:
    urlpatterns.insert(0, path('admin/', admin.site.urls))

# Friendly 403 (logged-in-but-no-role) instead of a bare Forbidden.
handler403 = "console.views.permission_denied"
