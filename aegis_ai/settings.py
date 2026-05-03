"""
Django settings for aegis_ai project.

Security Notes:
  - SECRET_KEY loaded from environment variables
  - Email credentials loaded from environment variables
  - CSRF and session security enabled
  - Rate limiting middleware active
  - No secrets hardcoded in production
"""

import os
import ssl
from pathlib import Path
import dj_database_url

# ── Fix SSL certificate verification on macOS ─────────────────────────────────
# Python on macOS often lacks proper CA certificates, causing
# "CERTIFICATE_VERIFY_FAILED" errors when connecting to SMTP servers.
# This uses certifi's CA bundle as the trusted certificate store.
try:
    import certifi
    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
    os.environ.setdefault("SSL_CERT_DIR", os.path.dirname(certifi.where()))
except ImportError:
    pass  # certifi not installed; rely on system certificates

# ── Load .env file ────────────────────────────────────────────────────────────
# Read .env file manually (no external dependency needed)
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-!@@qa1km04siytkxg=*t@2mk&))dttj*i!hzv!jj$c9^sczcex",
)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in ("true", "1", "yes")

RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
ALLOWED_HOSTS = [RENDER_EXTERNAL_HOSTNAME] if RENDER_EXTERNAL_HOSTNAME else ["*"]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Local apps
    "users",
    "firewall",
    "stegoshield",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Custom security middleware
    "users.middleware.RateLimitMiddleware",
]

ROOT_URLCONF = "aegis_ai.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "aegis_ai.wsgi.application"

# Database
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

if "DATABASE_URL" in os.environ:
    DATABASES["default"] = dj_database_url.config(
        default=os.environ.get("DATABASE_URL"),
        conn_max_age=600,
        conn_health_checks=True,
    )

# Custom user model
AUTH_USER_MODEL = "users.CustomUser"

# Authentication redirects
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/login/"

# Password validation
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

# Media files (uploads)
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Fernet encryption key (32 url-safe base64-encoded bytes)
FERNET_KEY = os.environ.get(
    "FERNET_KEY", "zKxYq3Hv8mNpR2Lw5TdUiOeAjBcFsGhX4lQkPnVyWZE="
).encode()

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# =============================================================================
# EMAIL CONFIGURATION (SendGrid / Gmail / any SMTP provider)
# =============================================================================
# Configure your SMTP credentials in the .env file.

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.sendgrid.net")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get("EMAIL_FROM", "") or "noreply@aegis-ai.com"

# Fallback to console backend if SMTP credentials not configured
_is_placeholder = (
    not EMAIL_HOST_USER
    or not EMAIL_HOST_PASSWORD
    or EMAIL_HOST_PASSWORD.startswith("your-")
    or "@example.com" in EMAIL_HOST_USER
)
if _is_placeholder:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# =============================================================================
# SESSION SECURITY
# =============================================================================
SESSION_COOKIE_HTTPONLY = True  # Prevent JS access to session cookie
SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_AGE = 3600  # 1 hour session expiry

# In production, enable these:
# SESSION_COOKIE_SECURE = True  # HTTPS only
# CSRF_COOKIE_SECURE = True     # HTTPS only
# SECURE_SSL_REDIRECT = True    # Redirect HTTP to HTTPS

# =============================================================================
# LOGGING
# =============================================================================
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "users": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}
