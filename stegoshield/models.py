"""
stegoshield/models.py – Audit logging and access tokens for STEGOSHIELD.

Models:
  - StegoLog:         Immutable audit trail for every encode/decode operation.
  - StegoAccessToken: Optional cryptographic token for decode validation.
"""

import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class StegoLog(models.Model):
    """Audit log for every STEGOSHIELD encode/decode operation."""

    ACTION_CHOICES = [
        ("ENCODE", "Encode"),
        ("DECODE", "Decode"),
    ]

    METHOD_CHOICES = [
        ("TEXT", "Text"),
        ("IMAGE", "Image"),
    ]

    STATUS_CHOICES = [
        ("SUCCESS", "Success"),
        ("FAILED", "Failed"),
        ("UNAUTHORIZED", "Unauthorized"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="stego_logs",
    )
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES)
    message_hash = models.CharField(
        max_length=64,
        blank=True,
        help_text="SHA-256 hash of the original message (for audit without storing plaintext).",
    )
    secret_message = models.TextField(blank=True, help_text="Encrypted secret message")
    cover_text = models.TextField(blank=True, help_text="Encrypted cover text or filename")
    passkey = models.CharField(max_length=255, blank=True, help_text="Encrypted passkey")
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    details = models.JSONField(
        default=dict,
        blank=True,
        help_text="Extra metadata about the operation.",
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        verbose_name = "STEGOSHIELD Log"
        verbose_name_plural = "STEGOSHIELD Logs"

    def __str__(self):
        return f"[{self.action}] {self.status} — {self.user} @ {self.timestamp:%Y-%m-%d %H:%M}"

    def decrypt_value(self, field_value):
        if not field_value:
            return ""
        try:
            from firewall.encryption import decrypt
            return decrypt(field_value)
        except Exception:
            return field_value

    @property
    def decrypted_secret(self):
        return self.decrypt_value(self.secret_message)
        
    @property
    def decrypted_cover(self):
        return self.decrypt_value(self.cover_text)
        
    @property
    def decrypted_passkey(self):
        return self.decrypt_value(self.passkey)


class StegoAccessToken(models.Model):
    """
    Optional token-based decode validation.

    The sender can generate a single-use token when encoding a message.
    The recipient must supply this token to decode.
    """

    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="stego_tokens_created",
    )
    token = models.CharField(max_length=64, unique=True, db_index=True)
    recipient_role = models.CharField(
        max_length=20,
        blank=True,
        help_text="Intended recipient role (ADMIN / EMPLOYEE).",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    used_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="stego_tokens_used",
    )
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "STEGOSHIELD Access Token"
        verbose_name_plural = "STEGOSHIELD Access Tokens"

    def __str__(self):
        status = "Used" if self.used else ("Expired" if self.is_expired else "Active")
        return f"Token {self.token[:8]}… [{status}] by {self.creator}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.used and not self.is_expired

    def mark_used(self, user):
        """Mark this token as used by the given user."""
        self.used = True
        self.used_by = user
        self.used_at = timezone.now()
        self.save(update_fields=["used", "used_by", "used_at"])

    @classmethod
    def create_token(cls, creator, recipient_role="", hours_valid=24):
        """Generate a new cryptographic access token."""
        return cls.objects.create(
            creator=creator,
            token=secrets.token_urlsafe(48),
            recipient_role=recipient_role,
            expires_at=timezone.now() + timedelta(hours=hours_valid),
        )
