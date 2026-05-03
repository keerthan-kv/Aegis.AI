"""
stegoshield/urls.py – URL configuration for STEGOSHIELD module.
"""

from django.urls import path

from . import views

urlpatterns = [
    # Page views
    path("stegoshield/", views.stegoshield_home, name="stegoshield_home"),
    path("stegoshield/encode/", views.encode_message, name="stegoshield_encode"),
    path("stegoshield/decode/", views.decode_message, name="stegoshield_decode"),
    path("stegoshield/download/", views.download_stego_file, name="stegoshield_download_file"),

    # JSON API endpoints
    path("api/stegoshield/encode-message/", views.stegoshield_api_encode, name="stegoshield_api_encode"),
    path("api/stegoshield/decode-message/", views.stegoshield_api_decode, name="stegoshield_api_decode"),
]
