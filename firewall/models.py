import json
import logging
from django.db import models
from django.conf import settings

from .encryption import decrypt


class TokenMap(models.Model):
    """Maps a token label to its encrypted original sensitive value."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token_label = models.CharField(max_length=30)        # e.g. [EMAIL_TOKEN], [API_KEY_TOKEN]
    encrypted_value = models.TextField()                  # Fernet-encrypted original
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.token_label} ({self.user.username})"


class PromptLog(models.Model):
    """Audit log for every prompt submitted through the firewall."""

    ACTION_CHOICES = [
        ("ALLOW", "Allow"),
        ("BLOCK", "Block"),
        ("TOKENIZE", "Tokenize"),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    original_prompt = models.TextField()
    processed_prompt = models.TextField(blank=True)
    detected_types = models.JSONField(default=list)       # list of dtype strings
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    reasons = models.JSONField(default=list)
    risk_score = models.IntegerField(default=0)           # 0–100
    risk_level = models.CharField(max_length=10, default="LOW")  # LOW/MODERATE/HIGH/SEVERE/CRITICAL
    ai_response = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.action}] {self.user} @ {self.timestamp:%Y-%m-%d %H:%M}"

    def detected_types_display(self):
        return ", ".join(self.detected_types) if self.detected_types else "None"

    @property
    def decrypted_original_prompt(self):
        """Decrypt the stored original_prompt on-the-fly for display.

        Falls back to the raw stored value if decryption fails
        (e.g. legacy rows that were saved before encryption was enabled).
        """
        try:
            return decrypt(self.original_prompt)
        except Exception:
            logger = logging.getLogger(__name__)
            logger.warning(
                "Could not decrypt original_prompt for PromptLog id=%s; "
                "returning raw value (may be a legacy unencrypted row).",
                self.pk,
            )
            return self.original_prompt
