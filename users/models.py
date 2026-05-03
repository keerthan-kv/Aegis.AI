import secrets
import string
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

class CustomUser(AbstractUser):
    # Role Choices
    INTERN = "INTERN"
    EMPLOYEE = "EMPLOYEE"
    ADMIN = "ADMIN"
    SUPER_ADMIN = "SUPER_ADMIN"

    ROLE_CHOICES = [
        (INTERN, "Intern"),
        (EMPLOYEE, "Employee"),
        (ADMIN, "Admin"),
        (SUPER_ADMIN, "Super Admin"),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=INTERN)

    # Email Verification
    email_verified = models.BooleanField(default=False)

    # Account Lockout
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(blank=True, null=True)

    # Password Reset
    password_reset_token = models.CharField(max_length=64, blank=True, null=True)
    password_reset_token_created_at = models.DateTimeField(blank=True, null=True)

    # Employee Approval Flow
    is_approved = models.BooleanField(default=False)

    # Admin Security: MFA (Optional)
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)

    full_name = models.CharField(max_length=150, blank=True, default="")

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    def is_super_admin_role(self):
        return self.role == self.SUPER_ADMIN

    def is_admin_role(self):
        return self.role in [self.ADMIN, self.SUPER_ADMIN]

    def is_employee_role(self):
        return self.role in [self.EMPLOYEE, self.ADMIN, self.SUPER_ADMIN]

    def is_intern_role(self):
        return self.role in [self.INTERN, self.EMPLOYEE, self.ADMIN, self.SUPER_ADMIN]

    @property
    def is_account_locked(self):
        if self.account_locked_until and timezone.now() < self.account_locked_until:
            return True
        return False

    def record_failed_login(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.account_locked_until = timezone.now() + timedelta(minutes=30)
        self.save(update_fields=["failed_login_attempts", "account_locked_until"])

    def reset_failed_logins(self):
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=["failed_login_attempts", "account_locked_until"])

    def generate_password_reset_token(self):
        self.password_reset_token = secrets.token_urlsafe(48)
        self.password_reset_token_created_at = timezone.now()
        self.save(update_fields=["password_reset_token", "password_reset_token_created_at"])
        return self.password_reset_token

    def verify_password_reset_token(self, token):
        if not self.password_reset_token or not self.password_reset_token_created_at:
            return False
        if timezone.now() > self.password_reset_token_created_at + timedelta(minutes=15):
            return False
        return self.password_reset_token == token

    def clear_password_reset_token(self):
        self.password_reset_token = None
        self.password_reset_token_created_at = None
        self.save(update_fields=["password_reset_token", "password_reset_token_created_at"])


class OTPToken(models.Model):
    """Secure OTP Token model with hashing and attempt tracking."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otp_tokens")
    otp_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)
    is_used = models.BooleanField(default=False)

    @classmethod
    def generate_for_user(cls, user):
        """Generate a secure 6-digit OTP."""
        # Invalidate previous active OTPs
        cls.objects.filter(user=user, is_used=False).update(is_used=True)

        otp_raw = "".join(secrets.choice(string.digits) for _ in range(6))
        otp_hash = make_password(otp_raw)
        expires = timezone.now() + timedelta(minutes=5)  # 5 minute expiry
        cls.objects.create(user=user, otp_hash=otp_hash, expires_at=expires)
        return otp_raw

    def verify(self, otp_raw):
        """Verify OTP with attempt limits and expiry check."""
        if self.is_used:
            return False, "OTP already used."
        if timezone.now() > self.expires_at:
            return False, "OTP has expired."
        if self.attempts >= 3:
            self.is_used = True
            self.save(update_fields=["is_used", "attempts"])
            return False, "Too many failed attempts. OTP invalidated."
        
        if check_password(otp_raw, self.otp_hash):
            self.is_used = True
            self.save(update_fields=["is_used"])
            return True, "OTP verified."
        
        self.attempts += 1
        self.save(update_fields=["attempts"])
        return False, "Invalid OTP."


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.user} - {self.action} at {self.timestamp}"


class LoginAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    successful = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    device_info = models.CharField(max_length=255, blank=True, null=True)


class EmployeeApproval(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="approval_request")
    status = models.CharField(
        max_length=20,
        choices=[("PENDING", "Pending"), ("APPROVED", "Approved"), ("REJECTED", "Rejected")],
        default="PENDING"
    )
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="approvals_reviewed")
    timestamp = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def approve(self, admin_user):
        self.status = "APPROVED"
        self.reviewed_by = admin_user
        self.save()
        self.user.is_approved = True
        self.user.save(update_fields=["is_approved"])
        
    def reject(self, admin_user):
        self.status = "REJECTED"
        self.reviewed_by = admin_user
        self.save()
        self.user.is_approved = False
        self.user.save(update_fields=["is_approved"])
