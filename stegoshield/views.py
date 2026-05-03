"""
stegoshield/views.py – Page views and API endpoints for STEGOSHIELD.

Views:
  - stegoshield_home:       Main page with tabbed Encode / Decode UI
  - encode_message:         POST handler for encoding (TEXT or FILE)
  - decode_message:         POST handler for decoding (TEXT or FILE)
  - download_stego_file:    Serve the encoded stego file as a download
  - stegoshield_api_encode: JSON API endpoint
  - stegoshield_api_decode: JSON API endpoint

Fix: stego files are saved to a temp directory on disk (not session)
     to avoid Django session size limits with large files (PDFs, etc.).

All views enforce RBAC (Admin + Employee only) and log every action.
"""

import base64
import json
import logging
import os
import uuid

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from users.decorators import roles_required
from .engine import (
    text_encode,
    text_decode,
    file_encode,
    file_decode,
    message_hash,
)
from .models import StegoLog

logger = logging.getLogger(__name__)

ALLOWED_ROLES = ["ADMIN", "EMPLOYEE"]

# Temp directory inside MEDIA_ROOT for stego files awaiting download
_STEGO_TEMP_DIR = os.path.join(settings.MEDIA_ROOT, "stego_temp")


def _ensure_temp_dir():
    """Create the stego temp directory if it doesn't exist."""
    os.makedirs(_STEGO_TEMP_DIR, exist_ok=True)


def _save_stego_to_disk(stego_bytes: bytes, filename: str) -> str:
    """
    Save stego_bytes to a uniquely named temp file on disk.
    Returns the full path of the saved file.
    """
    _ensure_temp_dir()
    unique_id = uuid.uuid4().hex
    ext = os.path.splitext(filename)[1] or ".bin"
    temp_name = f"{unique_id}{ext}"
    temp_path = os.path.join(_STEGO_TEMP_DIR, temp_name)
    with open(temp_path, "wb") as f:
        f.write(stego_bytes)
    return temp_path


def _get_client_ip(request):
    """Extract client IP from request headers."""
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _log_action(user, action, method, status, msg_hash="", ip="", details=None, secret_msg="", cover="", key=""):
    """Create a StegoLog entry."""
    from firewall.encryption import encrypt
    enc_secret = encrypt(secret_msg) if secret_msg else ""
    enc_cover = encrypt(cover) if cover else ""
    enc_key = encrypt(key) if key else ""
    
    StegoLog.objects.create(
        user=user,
        action=action,
        method=method,
        status=status,
        message_hash=msg_hash,
        secret_message=enc_secret,
        cover_text=enc_cover,
        passkey=enc_key,
        ip_address=ip,
        details=details or {},
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE VIEWS
# ═══════════════════════════════════════════════════════════════════════════════

@login_required(login_url="/login/")
@roles_required(ALLOWED_ROLES)
def stegoshield_home(request):
    """Main STEGOSHIELD page with encode/decode tabs."""
    recent_logs = StegoLog.objects.filter(user=request.user).order_by("-timestamp")[:10]
    total_operations = StegoLog.objects.filter(user=request.user).count()
    return render(request, "stegoshield/stegoshield.html", {
        "recent_logs": recent_logs,
        "total_operations": total_operations,
    })


@login_required(login_url="/login/")
@roles_required(ALLOWED_ROLES)
@require_POST
def encode_message(request):
    """Handle encoding via form POST — TEXT or FILE method."""
    method = request.POST.get("method", "TEXT").upper()
    secret = request.POST.get("secret_message", "").strip()
    passkey = request.POST.get("passkey", "")
    ip = _get_client_ip(request)

    result = {"tab": "encode"}

    if not secret:
        messages.warning(request, "Please enter a secret message to encode.")
        return redirect("stegoshield_home")

    try:
        if method == "FILE":
            cover_file = request.FILES.get("cover_file")
            if not cover_file:
                messages.warning(request, "Please select a cover file.")
                return redirect("stegoshield_home")

            cover_bytes = cover_file.read()
            stego_bytes = file_encode(cover_bytes, secret, passkey)

            # Preserve original file extension so the download matches
            original_name = cover_file.name
            name_base, ext = os.path.splitext(original_name)
            stego_filename = f"stego_{name_base}{ext}"

            # ✅ Save to disk — avoids session size limits for large files
            temp_path = _save_stego_to_disk(stego_bytes, stego_filename)

            # Store only the temp path + display name in session (tiny payload)
            request.session["stego_temp_path"] = temp_path
            request.session["stego_display_name"] = stego_filename
            request.session["stego_content_type"] = (
                cover_file.content_type or "application/octet-stream"
            )
            request.session.modified = True

            _log_action(
                request.user, "ENCODE", "FILE", "SUCCESS",
                msg_hash=message_hash(secret), ip=ip,
                secret_msg=secret, cover=original_name, key=passkey,
                details={
                    "cover_filename": original_name,
                    "cover_size_bytes": len(cover_bytes),
                    "stego_size_bytes": len(stego_bytes),
                },
            )

            result.update({
                "status": "success",
                "method": "FILE",
                "message": "Message embedded in file successfully!",
                "has_download": True,
                "stego_filename": stego_filename,
                "original_filename": original_name,
            })

        else:  # TEXT
            cover_text = request.POST.get("cover_text", "").strip()
            if not cover_text:
                messages.warning(request, "Please enter cover text.")
                return redirect("stegoshield_home")

            encoded = text_encode(cover_text, secret, passkey)

            _log_action(
                request.user, "ENCODE", "TEXT", "SUCCESS",
                msg_hash=message_hash(secret), ip=ip,
                secret_msg=secret, cover=cover_text, key=passkey,
                details={"cover_length": len(cover_text)},
            )

            result.update({
                "status": "success",
                "method": "TEXT",
                "message": "Message encoded in text successfully!",
                "encoded_text": encoded,
            })

    except ValueError as e:
        _log_action(
            request.user, "ENCODE", method, "FAILED",
            msg_hash=message_hash(secret) if secret else "", ip=ip,
            secret_msg=secret, key=passkey,
            details={"error": str(e)},
        )
        result.update({"status": "error", "method": method, "message": str(e)})

    except Exception as e:
        logger.exception("STEGOSHIELD encode error")
        _log_action(
            request.user, "ENCODE", method, "FAILED", ip=ip,
            secret_msg=secret, key=passkey,
            details={"error": str(e)},
        )
        result.update({
            "status": "error",
            "method": method,
            "message": "An unexpected error occurred during encoding.",
        })

    recent_logs = StegoLog.objects.filter(user=request.user).order_by("-timestamp")[:10]
    total_operations = StegoLog.objects.filter(user=request.user).count()
    return render(request, "stegoshield/stegoshield.html", {
        "result": result,
        "recent_logs": recent_logs,
        "total_operations": total_operations,
    })


@login_required(login_url="/login/")
@roles_required(ALLOWED_ROLES)
@require_POST
def decode_message(request):
    """Handle decoding via form POST — TEXT or FILE method."""
    method = request.POST.get("method", "TEXT").upper()
    passkey = request.POST.get("passkey", "")
    ip = _get_client_ip(request)

    result = {"tab": "decode"}

    try:
        if method == "FILE":
            stego_file = request.FILES.get("stego_file")
            if not stego_file:
                messages.warning(request, "Please select the stego file to decode.")
                return redirect("stegoshield_home")

            stego_bytes = stego_file.read()
            decoded = file_decode(stego_bytes, passkey)

            _log_action(
                request.user, "DECODE", "FILE", "SUCCESS",
                msg_hash=message_hash(decoded), ip=ip,
                secret_msg=decoded, cover=stego_file.name, key=passkey,
                details={"filename": stego_file.name, "file_size": len(stego_bytes)},
            )

            result.update({
                "status": "success",
                "method": "FILE",
                "message": "Message decoded successfully!",
                "decoded_text": decoded,
            })

        else:  # TEXT
            encoded_text = request.POST.get("encoded_text", "")
            if not encoded_text:
                messages.warning(request, "Please paste the encoded text.")
                return redirect("stegoshield_home")

            decoded = text_decode(encoded_text, passkey)

            _log_action(
                request.user, "DECODE", "TEXT", "SUCCESS",
                msg_hash=message_hash(decoded), ip=ip,
                secret_msg=decoded, key=passkey, cover="<Pasted Text>"
            )

            result.update({
                "status": "success",
                "method": "TEXT",
                "message": "Message decoded successfully!",
                "decoded_text": decoded,
            })

    except ValueError as e:
        error_msg = str(e)
        status = "UNAUTHORIZED" if "wrong passkey" in error_msg.lower() else "FAILED"
        _log_action(
            request.user, "DECODE", method, status, ip=ip,
            key=passkey,
            details={"error": error_msg},
        )
        result.update({
            "status": "unauthorized" if status == "UNAUTHORIZED" else "error",
            "method": method,
            "message": error_msg,
        })

    except Exception as e:
        logger.exception("STEGOSHIELD decode error")
        _log_action(
            request.user, "DECODE", method, "FAILED", ip=ip,
            key=passkey,
            details={"error": str(e)},
        )
        result.update({
            "status": "error",
            "method": method,
            "message": "An unexpected error occurred during decoding.",
        })

    recent_logs = StegoLog.objects.filter(user=request.user).order_by("-timestamp")[:10]
    total_operations = StegoLog.objects.filter(user=request.user).count()
    return render(request, "stegoshield/stegoshield.html", {
        "result": result,
        "recent_logs": recent_logs,
        "total_operations": total_operations,
    })


@login_required(login_url="/login/")
@roles_required(ALLOWED_ROLES)
def download_stego_file(request):
    """
    Serve the encoded stego file as a real file download.

    Reads the temp file path from session, streams it to the browser
    with the correct Content-Disposition header, then deletes the temp file.
    """
    temp_path = request.session.pop("stego_temp_path", None)
    display_name = request.session.pop("stego_display_name", "stego_output")
    content_type = request.session.pop("stego_content_type", "application/octet-stream")
    request.session.modified = True

    if not temp_path or not os.path.exists(temp_path):
        messages.warning(
            request,
            "Encoded file not found. Please encode the message again and download immediately."
        )
        return redirect("stegoshield_home")

    try:
        # Open the file and stream it — Django closes it after sending
        f = open(temp_path, "rb")
        response = FileResponse(
            f,
            content_type=content_type,
            as_attachment=True,
            filename=display_name,
        )
        # Schedule temp file deletion after response is sent
        response.close = lambda: (f.close(), _delete_temp(temp_path))
        return response

    except Exception as e:
        logger.exception("STEGOSHIELD download error")
        messages.error(request, "Failed to serve download. Please encode and try again.")
        return redirect("stegoshield_home")


def _delete_temp(path: str):
    """Silently delete a temp file."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# JSON API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@csrf_exempt
@require_POST
def stegoshield_api_encode(request):
    """
    API: POST /api/stegoshield/encode-message/

    JSON body  → { "method":"TEXT", "secret_message":"...", "cover_text":"...", "passkey":"..." }
    Multipart  → method=FILE, cover_file=<file upload>, secret_message=..., passkey=...
    """
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Authentication required."}, status=401)
    if request.user.role not in ALLOWED_ROLES:
        _log_action(request.user, "ENCODE", "TEXT", "UNAUTHORIZED",
                    ip=_get_client_ip(request))
        return JsonResponse({"error": "Access denied."}, status=403)

    ip = _get_client_ip(request)
    try:
        if request.content_type and "json" in request.content_type:
            body = json.loads(request.body)
        else:
            body = request.POST

        method = body.get("method", "TEXT").upper()
        secret = body.get("secret_message", "").strip()
        passkey = body.get("passkey", "")

        if not secret:
            return JsonResponse({"error": "secret_message is required."}, status=400)

        if method == "TEXT":
            cover = body.get("cover_text", "").strip()
            if not cover:
                return JsonResponse({"error": "cover_text is required."}, status=400)
            encoded = text_encode(cover, secret, passkey)
            _log_action(request.user, "ENCODE", "TEXT", "SUCCESS",
                        msg_hash=message_hash(secret), ip=ip)
            return JsonResponse({"status": "success", "encoded_text": encoded})

        elif method == "FILE":
            cover_file = request.FILES.get("cover_file")
            if not cover_file:
                return JsonResponse({"error": "cover_file is required."}, status=400)
            stego_bytes = file_encode(cover_file.read(), secret, passkey)
            _log_action(request.user, "ENCODE", "FILE", "SUCCESS",
                        msg_hash=message_hash(secret), ip=ip)
            return JsonResponse({
                "status": "success",
                "stego_file_b64": base64.b64encode(stego_bytes).decode("ascii"),
            })

        else:
            return JsonResponse({"error": f"Unknown method: {method}"}, status=400)

    except ValueError as e:
        return JsonResponse({"error": str(e)}, status=400)
    except Exception as e:
        logger.exception("API encode error")
        return JsonResponse({"error": "Internal server error."}, status=500)


@csrf_exempt
@require_POST
def stegoshield_api_decode(request):
    """
    API: POST /api/stegoshield/decode-message/

    JSON body  → { "method":"TEXT", "encoded_text":"...", "passkey":"..." }
    Multipart  → method=FILE, stego_file=<file upload>, passkey=...
    """
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Authentication required."}, status=401)
    if request.user.role not in ALLOWED_ROLES:
        _log_action(request.user, "DECODE", "TEXT", "UNAUTHORIZED",
                    ip=_get_client_ip(request))
        return JsonResponse({"error": "Access denied."}, status=403)

    ip = _get_client_ip(request)
    try:
        if request.content_type and "json" in request.content_type:
            body = json.loads(request.body)
        else:
            body = request.POST

        method = body.get("method", "TEXT").upper()
        passkey = body.get("passkey", "")

        if method == "TEXT":
            encoded_text = body.get("encoded_text", "")
            if not encoded_text:
                return JsonResponse({"error": "encoded_text is required."}, status=400)
            decoded = text_decode(encoded_text, passkey)
            _log_action(request.user, "DECODE", "TEXT", "SUCCESS",
                        msg_hash=message_hash(decoded), ip=ip)
            return JsonResponse({"status": "success", "decoded_text": decoded})

        elif method == "FILE":
            stego_file = request.FILES.get("stego_file")
            if not stego_file:
                return JsonResponse({"error": "stego_file is required."}, status=400)
            decoded = file_decode(stego_file.read(), passkey)
            _log_action(request.user, "DECODE", "FILE", "SUCCESS",
                        msg_hash=message_hash(decoded), ip=ip)
            return JsonResponse({"status": "success", "decoded_text": decoded})

        else:
            return JsonResponse({"error": f"Unknown method: {method}"}, status=400)

    except ValueError as e:
        status_str = "UNAUTHORIZED" if "wrong passkey" in str(e).lower() else "FAILED"
        _log_action(request.user, "DECODE", method, status_str, ip=ip,
                    details={"error": str(e)})
        return JsonResponse({"error": str(e)},
                            status=403 if status_str == "UNAUTHORIZED" else 400)
    except Exception as e:
        logger.exception("API decode error")
        return JsonResponse({"error": "Internal server error."}, status=500)
