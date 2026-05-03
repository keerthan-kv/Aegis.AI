"""
users/email_service.py – Email sending service using SMTP (Gmail / Brevo / any provider).

This module sends real emails for:
  - OTP verification during signup
  - Password reset links

Backend modes:
  - SMTP (production): Real emails sent via Gmail/Brevo SMTP
  - Console (development): Emails printed to terminal — still returns True

Security Notes:
  - Uses Django's SMTP backend configured via environment variables
  - OTP is generated server-side with `secrets` module (CSPRNG)
  - No API keys are hardcoded — all from environment variables
"""

import logging

from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)


def _is_console_backend():
    """Check if using the console email backend (development mode)."""
    return "console" in getattr(settings, "EMAIL_BACKEND", "")


def send_otp_email(user, otp):
    """
    Send OTP verification email to the user.

    Args:
        user: CustomUser instance
        otp: 6-digit OTP string

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    subject = "Aegis.AI — Verify Your Email"

    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Inter', -apple-system, sans-serif; background: #f8f9fc; margin: 0; padding: 0; }}
            .container {{ max-width: 520px; margin: 40px auto; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb; overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #4F46E5, #6366F1); padding: 32px 40px; text-align: center; }}
            .header h1 {{ color: #ffffff; font-size: 24px; font-weight: 800; letter-spacing: -0.5px; margin: 0; }}
            .header p {{ color: rgba(255,255,255,0.85); font-size: 14px; margin-top: 6px; }}
            .body {{ padding: 36px 40px; }}
            .body p {{ color: #4B5563; font-size: 15px; line-height: 1.7; margin: 0 0 16px; }}
            .otp-box {{ background: #f1f3f9; border: 2px dashed #4F46E5; border-radius: 10px; text-align: center; padding: 24px; margin: 24px 0; }}
            .otp-code {{ font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #4F46E5; font-family: 'JetBrains Mono', monospace; }}
            .otp-note {{ font-size: 13px; color: #6B7280; margin-top: 8px; }}
            .footer {{ padding: 20px 40px; background: #f8f9fc; border-top: 1px solid #e5e7eb; text-align: center; }}
            .footer p {{ color: #9CA3AF; font-size: 12px; margin: 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Aegis.AI</h1>
                <p>Email Verification</p>
            </div>
            <div class="body">
                <p>Hello <strong>{user.full_name or user.username}</strong>,</p>
                <p>Thank you for creating a Aegis.AI account. Use the OTP below to verify your email address:</p>
                <div class="otp-box">
                    <div class="otp-code">{otp}</div>
                    <div class="otp-note">This code expires in 10 minutes</div>
                </div>
                <p>If you didn't create an account with Aegis.AI, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>🔒 This is an automated message from Aegis.AI — Secure AI Prompt Firewall</p>
            </div>
        </div>
    </body>
    </html>
    """

    plain_message = (
        f"Hello {user.full_name or user.username},\n\n"
        f"Your Aegis.AI verification code is: {otp}\n\n"
        f"This code expires in 10 minutes.\n\n"
        f"If you didn't create this account, please ignore this email.\n\n"
        f"— Aegis.AI Team"
    )

    try:
        sent = send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        if _is_console_backend():
            logger.info(f"[CONSOLE MODE] OTP for {user.email}: {otp}")
            print(f"\n{'='*60}")
            print(f"  📧 OTP for {user.email}: {otp}")
            print(f"{'='*60}\n")
        else:
            logger.info(f"OTP email sent to {user.email} via SMTP")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {user.email}: {e}")
        return False


def send_password_reset_email(user, reset_url):
    """
    Send password reset email with a secure link.

    Args:
        user: CustomUser instance
        reset_url: Full URL for password reset

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    subject = "Aegis.AI — Reset Your Password"

    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Inter', -apple-system, sans-serif; background: #f8f9fc; margin: 0; padding: 0; }}
            .container {{ max-width: 520px; margin: 40px auto; background: #ffffff; border-radius: 12px; border: 1px solid #e5e7eb; overflow: hidden; }}
            .header {{ background: linear-gradient(135deg, #DC2626, #EF4444); padding: 32px 40px; text-align: center; }}
            .header h1 {{ color: #ffffff; font-size: 24px; font-weight: 800; letter-spacing: -0.5px; margin: 0; }}
            .header p {{ color: rgba(255,255,255,0.85); font-size: 14px; margin-top: 6px; }}
            .body {{ padding: 36px 40px; }}
            .body p {{ color: #4B5563; font-size: 15px; line-height: 1.7; margin: 0 0 16px; }}
            .btn {{ display: inline-block; background: #4F46E5; color: #ffffff !important; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 15px; margin: 16px 0; }}
            .url-fallback {{ background: #f1f3f9; border-radius: 8px; padding: 12px 16px; font-size: 13px; word-break: break-all; color: #4F46E5; margin-top: 16px; }}
            .footer {{ padding: 20px 40px; background: #f8f9fc; border-top: 1px solid #e5e7eb; text-align: center; }}
            .footer p {{ color: #9CA3AF; font-size: 12px; margin: 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔑 Password Reset</h1>
                <p>Aegis.AI Security</p>
            </div>
            <div class="body">
                <p>Hello <strong>{user.full_name or user.username}</strong>,</p>
                <p>We received a request to reset your password. Click the button below to set a new password:</p>
                <p style="text-align:center">
                    <a href="{reset_url}" class="btn">Reset Password</a>
                </p>
                <p>Or copy and paste this link into your browser:</p>
                <div class="url-fallback">{reset_url}</div>
                <p style="color:#DC2626;font-size:13px;margin-top:20px">
                    ⚠️ This link expires in <strong>15 minutes</strong>. If you didn't request this, your account is safe — no action needed.
                </p>
            </div>
            <div class="footer">
                <p>🔒 This is an automated message from Aegis.AI — Secure AI Prompt Firewall</p>
            </div>
        </div>
    </body>
    </html>
    """

    plain_message = (
        f"Hello {user.full_name or user.username},\n\n"
        f"We received a request to reset your Aegis.AI password.\n\n"
        f"Click this link to reset your password (expires in 15 minutes):\n"
        f"{reset_url}\n\n"
        f"If you didn't request this, your account is safe.\n\n"
        f"— Aegis.AI Team"
    )

    try:
        sent = send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        if _is_console_backend():
            logger.info(f"[CONSOLE MODE] Reset link for {user.email} printed to console")
            print(f"\n{'='*60}")
            print(f"  🔑 Reset link for {user.email}:")
            print(f"  {reset_url}")
            print(f"{'='*60}\n")
        else:
            logger.info(f"Password reset email sent to {user.email} via SMTP")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {e}")
        return False
