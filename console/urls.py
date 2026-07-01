from django.urls import path

from . import views

app_name = "console"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("users", views.users, name="users"),
    path("agents", views.agents, name="agents"),
    path("agents/edit", views.agent_edit, name="agent_edit"),
    path("agents/state", views.agent_set_state, name="agent_set_state"),
    path("releases", views.releases, name="releases"),
    path("witchhunt", views.witchhunt, name="witchhunt"),
    path("witchhunt/live", views.witchhunt_live, name="witchhunt_live"),
    path("witchhunt/tail.json", views.witchhunt_tail, name="witchhunt_tail"),
    path("witchhunt/<int:pk>", views.witchhunt_detail, name="witchhunt_detail"),
    path("tenant/<slug:slug>", views.tenant_detail, name="tenant"),
    path("tenant/<slug:slug>/approve", views.approve, name="approve"),
    path("tenant/<slug:slug>/revoke", views.revoke, name="revoke"),
    path("tenant/<slug:slug>/edit", views.tenant_edit, name="tenant_edit"),
    path("tenant/<slug:slug>/node/edit", views.node_edit, name="node_edit"),
    path("tenant/<slug:slug>/describe", views.set_description, name="describe"),
    path("tenant/<slug:slug>/grant/add", views.grant_add, name="grant_add"),
    path("tenant/<slug:slug>/grant/class", views.grant_set_class, name="grant_set_class"),
    path("tenant/<slug:slug>/grant/revoke", views.grant_revoke, name="grant_revoke"),
    path("tenant/<slug:slug>/token/mint", views.mint_join_token, name="mint_join_token"),
    path("tenant/<slug:slug>/token/revoke", views.revoke_join_token, name="revoke_join_token"),
    path("tenant/<slug:slug>/channel", views.set_channel, name="set_channel"),
    path("tenant/<slug:slug>/update", views.request_update, name="request_update"),
]
