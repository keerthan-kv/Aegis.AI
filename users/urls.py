"""
users/urls.py – URL configuration for all authentication flows.
"""

from django.urls import path
from . import views
from . import admin_views

urlpatterns = [
    # Authentication
    path("login/", views.login_view, name="login"),
    path("signup/", views.signup_view, name="signup"),
    path("logout/", views.logout_view, name="logout"),

    # Email Verification
    path("verify-otp/", views.verify_otp_view, name="verify_otp"),
    path("resend-otp/", views.resend_otp_view, name="resend_otp"),

    # Password Reset
    path("forgot-password/", views.forgot_password_view, name="forgot_password"),
    path("reset-password/<str:token>/", views.reset_password_view, name="reset_password"),

    # Admin Portal
    path("admin/", views.admin_login_view, name="admin_login"),
    path("admin-portal/", admin_views.admin_dashboard, name="admin_dashboard"),
    path("admin-portal/logs/", admin_views.admin_logs, name="admin_logs"),
    path("admin-portal/users/", admin_views.admin_user_management, name="admin_users"),
    path("admin-portal/approve/<int:approval_id>/", admin_views.admin_approve_employee, name="admin_approve"),
]
