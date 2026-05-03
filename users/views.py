import html
import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect, render
from django.utils import timezone

from .email_service import send_otp_email, send_password_reset_email
from .models import CustomUser, OTPToken, LoginAttempt, AuditLog, EmployeeApproval
from .validators import validate_password_strength

logger = logging.getLogger(__name__)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')

def admin_login_view(request):
    if request.user.is_authenticated:
        if request.user.is_admin_role():
            return redirect("admin_dashboard")
        return redirect("dashboard")

    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")
        ip_addr = get_client_ip(request)

        if not email or not password:
            messages.error(request, "Please enter both email and password.")
            return render(request, "users/admin_login.html")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            LoginAttempt.objects.create(ip_address=ip_addr, successful=False, device_info=request.META.get('HTTP_USER_AGENT'))
            messages.error(request, "Invalid credentials.")
            return render(request, "users/admin_login.html")

        if not user.is_admin_role():
            LoginAttempt.objects.create(ip_address=ip_addr, successful=False, device_info=request.META.get('HTTP_USER_AGENT'))
            messages.error(request, "Unauthorized access.")
            return render(request, "users/admin_login.html")

        if user.is_account_locked:
            messages.error(request, "Account locked. Please try again later.")
            return render(request, "users/admin_login.html")

        auth_user = authenticate(request, username=user.username, password=password)
        if auth_user is None:
            user.record_failed_login()
            LoginAttempt.objects.create(user=user, ip_address=ip_addr, successful=False, device_info=request.META.get('HTTP_USER_AGENT'))
            messages.error(request, "Invalid credentials.")
            return render(request, "users/admin_login.html")

        if not auth_user.email_verified:
            otp = OTPToken.generate_for_user(auth_user)
            send_otp_email(auth_user, otp)
            request.session["verify_user_id"] = auth_user.pk
            return redirect("verify_otp")

        auth_user.reset_failed_logins()
        login(request, auth_user)
        LoginAttempt.objects.create(user=auth_user, ip_address=ip_addr, successful=True, device_info=request.META.get('HTTP_USER_AGENT'))
        AuditLog.objects.create(user=auth_user, action="Admin Login", ip_address=ip_addr)
        return redirect("admin_dashboard")

    return render(request, "users/admin_login.html")

def login_view(request):
    if request.user.is_authenticated:
        if request.user.is_admin_role():
            return redirect("admin_dashboard")
        return redirect("dashboard")

    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")
        ip_addr = get_client_ip(request)

        if not email or not password:
            messages.error(request, "Please enter both email and password.")
            return render(request, "users/login.html")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            LoginAttempt.objects.create(ip_address=ip_addr, successful=False, device_info=request.META.get('HTTP_USER_AGENT'))
            messages.error(request, "Invalid email or password.")
            return render(request, "users/login.html")

        if user.is_account_locked:
            remaining = (user.account_locked_until - timezone.now()).seconds // 60
            messages.error(request, f"Account locked. Try again in {remaining + 1} minutes.")
            return render(request, "users/login.html")

        auth_user = authenticate(request, username=user.username, password=password)
        if auth_user is None:
            user.record_failed_login()
            LoginAttempt.objects.create(user=user, ip_address=ip_addr, successful=False, device_info=request.META.get('HTTP_USER_AGENT'))
            messages.error(request, "Invalid email or password.")
            return render(request, "users/login.html")

        if not auth_user.email_verified:
            otp = OTPToken.generate_for_user(auth_user)
            send_otp_email(auth_user, otp)
            messages.warning(request, "Please verify your email first.")
            request.session["verify_user_id"] = auth_user.pk
            return redirect("verify_otp")

        if not auth_user.is_approved and not auth_user.is_admin_role():
            messages.warning(request, "Your account is pending administrator approval.")
            return render(request, "users/approval_pending.html")

        auth_user.reset_failed_logins()
        login(request, auth_user)
        LoginAttempt.objects.create(user=auth_user, ip_address=ip_addr, successful=True, device_info=request.META.get('HTTP_USER_AGENT'))
        AuditLog.objects.create(user=auth_user, action="User Login", ip_address=ip_addr)
        
        if auth_user.is_admin_role():
            return redirect("admin_dashboard")
        return redirect("dashboard")

    return render(request, "users/login.html")

def signup_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        full_name = html.escape(request.POST.get("full_name", "").strip())
        email = request.POST.get("email", "").strip().lower()
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")
        role = request.POST.get("role", "INTERN").upper()

        if not all([full_name, email, password, confirm_password]):
            messages.error(request, "All fields are required.")
            return render(request, "users/signup.html", {"form_data": {"full_name": full_name, "email": email, "role": role}})

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "An account with this email already exists.")
            return render(request, "users/signup.html", {"form_data": {"full_name": full_name, "email": email, "role": role}})

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "users/signup.html", {"form_data": {"full_name": full_name, "email": email, "role": role}})

        password_errors = validate_password_strength(password)
        if password_errors:
            for err in password_errors:
                messages.error(request, err)
            return render(request, "users/signup.html", {"form_data": {"full_name": full_name, "email": email, "role": role}})

        # Security constraint: only allow INTERN or EMPLOYEE from public signup
        if role not in [CustomUser.INTERN, CustomUser.EMPLOYEE]:
            role = CustomUser.INTERN

        username = email.split("@")[0]
        base_username = username
        counter = 1
        while CustomUser.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        is_approved = False

        user = CustomUser.objects.create_user(
            username=username, email=email, password=password, full_name=full_name,
            role=role, email_verified=False, is_approved=is_approved
        )

        EmployeeApproval.objects.create(user=user)

        otp = OTPToken.generate_for_user(user)
        send_otp_email(user, otp)

        messages.success(request, "Account created! Please check your email for the verification code.")
        request.session["verify_user_id"] = user.pk
        return redirect("verify_otp")

    return render(request, "users/signup.html")

def verify_otp_view(request):
    user_id = request.session.get("verify_user_id")
    if not user_id:
        return redirect("login")

    try:
        user = CustomUser.objects.get(pk=user_id)
    except CustomUser.DoesNotExist:
        return redirect("signup")

    if request.method == "POST":
        otp_input = request.POST.get("otp", "").strip()
        if not otp_input or len(otp_input) != 6:
            messages.error(request, "Please enter a valid 6-digit OTP.")
            return render(request, "users/verify_otp.html", {"email": user.email})

        active_otp = OTPToken.objects.filter(user=user, is_used=False).order_by('-created_at').first()
        if not active_otp:
            messages.error(request, "No active OTP found. Please request a new one.")
            return render(request, "users/verify_otp.html", {"email": user.email})

        is_valid, msg = active_otp.verify(otp_input)
        if is_valid:
            user.email_verified = True
            user.save(update_fields=["email_verified"])
            request.session.pop("verify_user_id", None)
            AuditLog.objects.create(user=user, action="Email Verified", ip_address=get_client_ip(request))
            messages.success(request, "Email verified successfully!")
            return redirect("login")
        else:
            messages.error(request, msg)

    return render(request, "users/verify_otp.html", {"email": user.email})

def resend_otp_view(request):
    user_id = request.session.get("verify_user_id")
    if not user_id:
        return redirect("login")

    try:
        user = CustomUser.objects.get(pk=user_id)
    except CustomUser.DoesNotExist:
        return redirect("login")

    otp = OTPToken.generate_for_user(user)
    send_otp_email(user, otp)
    messages.success(request, "A new OTP has been sent.")
    return redirect("verify_otp")

def forgot_password_view(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()
        messages.success(request, "If an account exists, a reset link has been sent.")
        try:
            user = CustomUser.objects.get(email=email)
            token = user.generate_password_reset_token()
            reset_url = request.build_absolute_uri(f"/reset-password/{token}/")
            send_password_reset_email(user, reset_url)
            AuditLog.objects.create(user=user, action="Password Reset Requested", ip_address=get_client_ip(request))
        except CustomUser.DoesNotExist:
            pass
        return render(request, "users/forgot_password.html", {"email_sent": True})
    return render(request, "users/forgot_password.html")

def reset_password_view(request, token):
    try:
        user = CustomUser.objects.get(password_reset_token=token)
    except CustomUser.DoesNotExist:
        messages.error(request, "Invalid link.")
        return redirect("forgot_password")

    if not user.verify_password_reset_token(token):
        messages.error(request, "Expired link.")
        return redirect("forgot_password")

    if request.method == "POST":
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "users/reset_password.html", {"token": token})

        user.set_password(password)
        user.clear_password_reset_token()
        user.reset_failed_logins()
        user.save()
        AuditLog.objects.create(user=user, action="Password Reset Completed", ip_address=get_client_ip(request))
        messages.success(request, "Password reset successfully!")
        return redirect("login")
    return render(request, "users/reset_password.html", {"token": token})

def logout_view(request):
    if request.user.is_authenticated:
        AuditLog.objects.create(user=request.user, action="User Logout", ip_address=get_client_ip(request))
    logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect("login")
