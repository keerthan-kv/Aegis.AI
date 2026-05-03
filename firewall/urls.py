from django.urls import path
from . import views

urlpatterns = [
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("prompt/", views.prompt_view, name="prompt"),
    path("logs/", views.logs_view, name="logs"),
    path("logs/<int:log_id>/", views.log_detail_view, name="log_detail"),
]
