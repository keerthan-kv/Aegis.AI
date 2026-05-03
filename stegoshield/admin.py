"""
stegoshield/admin.py – Django admin registration for STEGOSHIELD models.
"""

from django.contrib import admin

from .models import StegoLog, StegoAccessToken


@admin.register(StegoLog)
class StegoLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "method", "status", "timestamp", "ip_address")
    list_filter = ("action", "method", "status", "user")
    readonly_fields = (
        "user", "action", "method", "status", "message_hash",
        "ip_address", "details", "timestamp",
    )
    search_fields = ("user__username", "message_hash")
    date_hierarchy = "timestamp"


@admin.register(StegoAccessToken)
class StegoAccessTokenAdmin(admin.ModelAdmin):
    list_display = ("token_short", "creator", "recipient_role", "created_at", "expires_at", "used")
    list_filter = ("used", "recipient_role")
    readonly_fields = ("token", "creator", "created_at")
    search_fields = ("token", "creator__username")

    @admin.display(description="Token")
    def token_short(self, obj):
        return f"{obj.token[:12]}…"
