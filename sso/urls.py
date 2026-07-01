from django.urls import path

from . import views

urlpatterns = [
    # "/" is owned by the console app (the dashboard); sso just handles /oidc/*.
    path("oidc/login", views.login, name="oidc-login"),
    path("oidc/callback", views.callback, name="oidc-callback"),
    path("oidc/logout", views.logout, name="oidc-logout"),
    path("oidc/me", views.me, name="oidc-me"),
]
