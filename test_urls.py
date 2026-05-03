import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_ai.settings')
django.setup()

from django.test import Client
from users.models import CustomUser

# Get or create super admin
admin_user = CustomUser.objects.filter(role="ADMIN").first()
if not admin_user:
    admin_user = CustomUser.objects.filter(is_superuser=True).first()

if admin_user:
    c = Client()
    c.force_login(admin_user)
    
    response = c.get('/admin-portal/')
    print(f"Status Code /admin-portal/: {response.status_code}")
    if response.status_code != 200:
        print(response.content.decode())

    response = c.get('/admin-portal/users/')
    print(f"Status Code /admin-portal/users/: {response.status_code}")
    if response.status_code != 200:
        print(response.content.decode())

    response = c.get('/admin-portal/logs/')
    print(f"Status Code /admin-portal/logs/: {response.status_code}")
    if response.status_code != 200:
        print(response.content.decode())
else:
    print("No admin user found to test with.")
