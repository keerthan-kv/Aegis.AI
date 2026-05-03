from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .models import CustomUser, AuditLog, LoginAttempt, EmployeeApproval

def is_admin(user):
    return user.is_authenticated and user.is_admin_role()

def is_super_admin(user):
    return user.is_authenticated and user.is_super_admin_role()

@login_required
@user_passes_test(is_admin, login_url='/login/')
def admin_dashboard(request):
    approvals = EmployeeApproval.objects.filter(status="PENDING")
    recent_logs = AuditLog.objects.all().order_by('-timestamp')[:10]
    return render(request, "users/admin_dashboard.html", {
        "approvals": approvals,
        "recent_logs": recent_logs,
    })

@login_required
@user_passes_test(is_admin, login_url='/login/')
def admin_approve_employee(request, approval_id):
    if request.method == "POST":
        try:
            approval = EmployeeApproval.objects.get(id=approval_id)
            action = request.POST.get("action")
            ip_addr = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
            if action == "approve":
                approval.approve(request.user)
                messages.success(request, f"Approved {approval.user.email}")
                AuditLog.objects.create(user=request.user, action=f"Approved Employee {approval.user.email}", ip_address=ip_addr)
            elif action == "reject":
                approval.reject(request.user)
                messages.warning(request, f"Rejected {approval.user.email}")
                AuditLog.objects.create(user=request.user, action=f"Rejected Employee {approval.user.email}", ip_address=ip_addr)
        except EmployeeApproval.DoesNotExist:
            messages.error(request, "Approval not found.")
    return redirect("admin_dashboard")

from firewall.models import PromptLog
from stegoshield.models import StegoLog

@login_required
@user_passes_test(is_admin, login_url='/login/')
def admin_logs(request):
    logs = AuditLog.objects.all().order_by('-timestamp')[:100]
    login_attempts = LoginAttempt.objects.all().order_by('-timestamp')[:100]
    prompt_logs = PromptLog.objects.select_related('user').all().order_by('-timestamp')[:100]
    stego_logs = StegoLog.objects.select_related('user').all().order_by('-timestamp')[:100]
    
    ip_addr = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
    AuditLog.objects.create(user=request.user, action="Viewed Logs", ip_address=ip_addr)
    return render(request, "users/admin_logs.html", {
        "logs": logs,
        "login_attempts": login_attempts,
        "prompt_logs": prompt_logs,
        "stego_logs": stego_logs,
    })

@login_required
@user_passes_test(is_admin, login_url='/login/')
def admin_user_management(request):
    if request.method == "POST":
        user_id = request.POST.get("user_id")
        action = request.POST.get("action", "update")
        
        try:
            u = CustomUser.objects.get(id=user_id)
            if u != request.user:
                if u.role == CustomUser.SUPER_ADMIN and not request.user.is_super_admin_role():
                    messages.error(request, "Only a Super Admin can modify or delete another Super Admin.")
                    return redirect("admin_users")

                ip_addr = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
                
                if action == "delete":
                    email = u.email
                    u.delete()
                    AuditLog.objects.create(user=request.user, action=f"Deleted user {email}", ip_address=ip_addr)
                    messages.success(request, f"Successfully deleted {email}")
                else:
                    new_role = request.POST.get("role")
                    new_approval = request.POST.get("approval")
                    if new_role and new_role in [c[0] for c in CustomUser.ROLE_CHOICES]:
                        if new_role == CustomUser.SUPER_ADMIN and not request.user.is_super_admin_role():
                            messages.error(request, "Only a Super Admin can assign the Super Admin role.")
                        else:
                            u.role = new_role
                    if new_approval in ["True", "False"]:
                        u.is_approved = (new_approval == "True")
                    u.save()
                    AuditLog.objects.create(user=request.user, action=f"Updated user {u.email} to Role: {u.role}, Approved: {u.is_approved}", ip_address=ip_addr)
                    messages.success(request, f"Successfully updated {u.email}")
            else:
                messages.error(request, "You cannot modify or delete your own account from this page.")
        except CustomUser.DoesNotExist:
            messages.error(request, "User not found.")
            
        return redirect("admin_users")

    query = request.GET.get("q", "").strip()
    if query:
        from django.db.models import Q
        users = CustomUser.objects.filter(
            Q(email__icontains=query) | Q(full_name__icontains=query) | Q(username__icontains=query)
        ).order_by('-date_joined')
    else:
        users = CustomUser.objects.all().order_by('-date_joined')
        
    return render(request, "users/admin_users.html", {
        "users": users,
        "roles": CustomUser.ROLE_CHOICES,
        "query": query,
    })
