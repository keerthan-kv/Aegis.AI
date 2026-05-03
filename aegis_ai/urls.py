from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect


def root_view(request):
    """Root entry point: redirect to dashboard if logged in, otherwise to login."""
    if request.user.is_authenticated:
        return redirect("dashboard")
    return redirect("login")


urlpatterns = [
    path("django-admin/", admin.site.urls),
    # Root → redirect based on auth status
    path("", root_view, name="root"),
    path("", include("firewall.urls")),
    path("", include("users.urls")),
    path("", include("stegoshield.urls")),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
