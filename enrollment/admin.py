from django.contrib import admin, messages

from . import services
from .models import Enrollment, Grant, JoinToken, SystemIdentity, Tenant


@admin.register(Grant)
class GrantAdmin(admin.ModelAdmin):
    list_display = ("tenant", "subject_kind", "subject", "verb_class",
                    "require_confirmation", "is_active")
    list_filter = ("tenant", "verb_class", "subject_kind", "is_active")
    search_fields = ("subject",)


@admin.register(SystemIdentity)
class SystemIdentityAdmin(admin.ModelAdmin):
    list_display = ("spiffe_id", "tenant", "role", "is_active", "cert_not_after")
    list_filter = ("role", "is_active", "tenant")
    search_fields = ("spiffe_id", "spki_fingerprint")
    readonly_fields = ("spki_fingerprint", "cert_pem", "created_at")


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ("slug", "name", "is_active", "created_at")
    search_fields = ("slug", "name")


@admin.register(JoinToken)
class JoinTokenAdmin(admin.ModelAdmin):
    list_display = ("id", "tenant", "label", "uses", "max_uses", "expires_at", "revoked")
    list_filter = ("tenant", "revoked")
    readonly_fields = ("token_hash", "uses", "created_at")


@admin.register(Enrollment)
class EnrollmentAdmin(admin.ModelAdmin):
    list_display = ("bound_name", "requested_name", "tenant", "state",
                    "short_fingerprint", "created_at", "cert_not_after")
    list_filter = ("tenant", "state")
    search_fields = ("spki_fingerprint", "bound_name", "requested_name")
    readonly_fields = ("spki_fingerprint", "csr_pem", "cert_pem", "spiffe_id",
                       "created_at", "approved_at", "revoked_at")
    actions = ("action_approve", "action_revoke")

    @admin.display(description="fingerprint")
    def short_fingerprint(self, obj):
        return obj.spki_fingerprint[:16]

    @admin.display(description="SPIFFE ID")
    def spiffe_id(self, obj):
        return obj.spiffe_id

    @admin.action(description="Approve (bind name = requested_name, issue cert)")
    def action_approve(self, request, queryset):
        ok = 0
        for e in queryset:
            try:
                services.approve(e, bound_name=e.requested_name or e.spki_fingerprint[:16],
                                 approved_by=request.user.get_username())
                ok += 1
            except services.EnrollmentError as exc:
                self.message_user(request, f"{e}: {exc}", level=messages.ERROR)
        if ok:
            self.message_user(request, f"approved {ok} enrollment(s)")

    @admin.action(description="Revoke")
    def action_revoke(self, request, queryset):
        for e in queryset:
            services.revoke(e, revoked_by=request.user.get_username())
        self.message_user(request, f"revoked {queryset.count()} enrollment(s)")
