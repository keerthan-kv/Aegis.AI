"""
Management command to create demo users for Aegis.AI.

Creates three demo users (admin, employee, intern) with email-verified accounts.
These are pre-verified so they can log in immediately for demo purposes.

Usage:
    python manage.py create_demo_users
"""

from django.core.management.base import BaseCommand

from users.models import CustomUser


class Command(BaseCommand):
    help = "Create demo users for Aegis.AI (admin, employee, intern)"

    DEMO_USERS = [
        {
            "username": "admin",
            "email": "admin@aegis.ai",
            "password": "Admin123!",
            "full_name": "Admin User",
            "role": "ADMIN",
            "is_staff": True,
            "is_superuser": True,
        },
        {
            "username": "employee",
            "email": "employee@aegis.ai",
            "password": "Emp123!!",
            "full_name": "Employee User",
            "role": "EMPLOYEE",
            "is_staff": False,
            "is_superuser": False,
        },
        {
            "username": "intern",
            "email": "intern@aegis.ai",
            "password": "Int123!!",
            "full_name": "Intern User",
            "role": "INTERN",
            "is_staff": False,
            "is_superuser": False,
        },
    ]

    def handle(self, *args, **options):
        for user_data in self.DEMO_USERS:
            username = user_data["username"]
            email = user_data["email"]

            if CustomUser.objects.filter(username=username).exists():
                self.stdout.write(
                    self.style.WARNING(f"  ⚠  User '{username}' already exists — skipping.")
                )
                continue

            user = CustomUser.objects.create_user(
                username=username,
                email=email,
                password=user_data["password"],
                full_name=user_data["full_name"],
                role=user_data["role"],
                is_staff=user_data["is_staff"],
                is_superuser=user_data["is_superuser"],
                email_verified=True,  # Pre-verified for demo
            )

            self.stdout.write(
                self.style.SUCCESS(
                    f"  ✓  Created {user_data['role']} user: {email} / {user_data['password']}"
                )
            )

        self.stdout.write(self.style.SUCCESS("\n  ✅ Demo users ready!"))
