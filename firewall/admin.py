from django.contrib import admin
from .models import TokenMap, PromptLog


@admin.register(TokenMap)
class TokenMapAdmin(admin.ModelAdmin):
    list_display = ("token_label", "user", "created_at")
    list_filter = ("user",)
    readonly_fields = ("encrypted_value",)


@admin.register(PromptLog)
class PromptLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "detected_types_display", "timestamp")
    list_filter = ("action", "user")
    readonly_fields = ("original_prompt", "processed_prompt", "ai_response", "reasons")
