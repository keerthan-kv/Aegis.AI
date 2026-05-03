import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_ai.settings')
django.setup()
from django.template.loader import render_to_string

try:
    render_to_string('users/admin_dashboard.html')
    print("SUCCESS dashboard")
except Exception as e:
    print("ERROR dashboard:", str(e))

try:
    render_to_string('users/admin_users.html')
    print("SUCCESS users")
except Exception as e:
    print("ERROR users:", str(e))

try:
    render_to_string('users/admin_logs.html')
    print("SUCCESS logs")
except Exception as e:
    print("ERROR logs:", str(e))
