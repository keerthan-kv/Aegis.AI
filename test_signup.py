import os
import django
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_ai.settings')
django.setup()

from django.test import Client

c = Client()
try:
    response = c.post('/signup/', {
        'full_name': 'Test User',
        'email': 'test2@example.com',
        'password': 'Password123!',
        'confirm_password': 'Password123!',
        'role': 'INTERN'
    })
    print("Status Code:", response.status_code)
    if response.status_code == 500:
        print("500 Error!")
except Exception as e:
    import traceback
    traceback.print_exc()
