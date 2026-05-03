from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser, OTPToken, AuditLog, LoginAttempt, EmployeeApproval

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = (
        "username",
        "email",
        "full_name",
        "role",
        "email_verified",
        "is_approved",
        "is_staff",
        "is_active",
        "failed_login_attempts",
    )
    list_filter = ("role", "email_verified", "is_approved", "is_staff", "is_active")
    search_fields = ("username", "email", "full_name")

    fieldsets = UserAdmin.fieldsets + (
        ("Role & Access", {"fields": ("role", "full_name", "is_approved")}),
        (
            "Email Verification",
            {"fields": ("email_verified",)},
        ),
        (
            "Security",
            {
                "fields": (
                    "failed_login_attempts",
                    "account_locked_until",
                    "password_reset_token",
                    "password_reset_token_created_at",
                    "mfa_enabled",
                )
            },
        ),
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        ("Role & Access", {"fields": ("role", "full_name", "email", "is_approved")}),
    )

    readonly_fields = (
        "password_reset_token_created_at",
        "password_reset_token",
    )

admin.site.register(OTPToken)
admin.site.register(AuditLog)
admin.site.register(LoginAttempt)
admin.site.register(EmployeeApproval)
