from django.contrib import admin

from .models import Operator


@admin.register(Operator)
class OperatorAdmin(admin.ModelAdmin):
    list_display = ("upn", "tier", "is_active", "last_login", "granted_by")
    list_filter = ("tier", "is_active")
    search_fields = ("upn", "oid", "display_name")
    readonly_fields = ("oid", "last_login", "created_at")
