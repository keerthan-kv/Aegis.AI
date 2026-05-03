"""
firewall/views.py – Main pipeline view connecting all modules.

Pipeline for prompt_view:
  1. Receive prompt from user
  2. scan() → list of detections
  3. apply_policy(role, detections) → action, reasons, tokenize_targets, block_details
  4. calculate_risk(role, detections) → risk_score, risk_level
  5. If risk_score >= 60 → upgrade ALLOW → BLOCK (defense-in-depth)

  ── BLOCK path ──────────────────────────────────────────────────────────────
  6. No masking, no AI call.
     Prompt is denied. Response shows risk %, risk level, and block reasons.

  ── TOKENIZE / ALLOW path ───────────────────────────────────────────────────
  6. tokenize() only the PII detections (email, phone, aadhaar) → masked prompt
  7. encrypt each original value and save TokenMap rows
  8. Call mock_ai(masked_prompt) → ai_response
  9. Log to PromptLog (with risk fields, action=TOKENIZE/ALLOW, masked response)
  10. Render structured Security Report
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from .scanner import scan
from .policy_engine import apply_policy, BLOCK_DTYPE_REASONS
from .tokenization import tokenize
from .encryption import encrypt
from .mock_ai import mock_ai
from .risk_scorer import calculate_risk
from .models import TokenMap, PromptLog


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@login_required(login_url="/login/")
def dashboard_view(request):
    """Show user role badge and navigation options."""
    recent_logs = PromptLog.objects.filter(user=request.user).order_by("-timestamp")[:5]
    total_submissions = PromptLog.objects.filter(user=request.user).count()
    last_log = PromptLog.objects.filter(user=request.user).order_by("-timestamp").first()
    context = {
        "recent_logs": recent_logs,
        "total_submissions": total_submissions,
        "last_submission": last_log.timestamp if last_log else None,
    }
    return render(request, "firewall/dashboard.html", context)


# ---------------------------------------------------------------------------
# Prompt Processing
# ---------------------------------------------------------------------------
@login_required(login_url="/login/")
def prompt_view(request):
    """Receive, scan, evaluate, score risk, log, and respond to a prompt."""
    result = None

    if request.method == "POST":
        original_prompt = request.POST.get("prompt", "").strip()

        if not original_prompt:
            messages.warning(request, "Please enter a prompt before submitting.")
            return render(request, "firewall/prompt.html")

        # Step 1: Scan
        detections = scan(original_prompt)
        detected_types = list({d.dtype for d in detections})

        # Step 2: Policy
        policy = apply_policy(request.user.role, detections)
        action = policy["action"]
        reasons = policy["reasons"]
        tokenize_targets = policy["tokenize_targets"]

        # Step 3: Risk Score
        risk = calculate_risk(request.user.role, detections)
        risk_score = risk["score"]
        risk_level = risk["level"]

        # Step 4: Defense-in-depth — risk score can upgrade ALLOW → BLOCK
        if risk["should_block"] and action == "ALLOW":
            action = "BLOCK"
            reasons.append(
                f"🚨 Risk score {risk_score}% exceeds threshold (≥60%) — automatic block."
            )

        processed_prompt = original_prompt
        ai_response = ""

        if action == "BLOCK":
            # ── BLOCK PATH ─────────────────────────────────────────────────
            # High-risk content detected. No masking, no AI call.
            # Build per-dtype block explanations for the UI.
            block_details = []
            seen = set()
            for d in detections:
                if d.dtype not in seen:
                    seen.add(d.dtype)
                    explanation = BLOCK_DTYPE_REASONS.get(
                        d.dtype,
                        f"{d.dtype.replace('_', ' ').title()} — blocked under Zero Trust policy."
                    )
                    block_details.append({
                        "dtype":       d.dtype.replace("_", " ").upper(),
                        "explanation": explanation,
                    })

            # Log the blocked prompt (no processed_prompt / ai_response)
            # Store the original prompt in encrypted form for data-at-rest security
            PromptLog.objects.create(
                user=request.user,
                original_prompt=encrypt(original_prompt),
                processed_prompt="[BLOCKED — not processed]",
                detected_types=detected_types,
                action=action,
                reasons=reasons,
                risk_score=risk_score,
                risk_level=risk_level,
                ai_response="[BLOCKED]",
            )

            result = {
                "original_prompt": original_prompt,
                "processed_prompt": None,
                "action":          action,
                "reasons":         reasons,
                "detected_types":  detected_types,
                "risk_score":      risk_score,
                "risk_level":      risk_level,
                "ai_response":     None,
                "block_details":   block_details,
            }

        else:
            # ── TOKENIZE / ALLOW PATH ──────────────────────────────────────
            # Mask only PII detections (email, phone, aadhaar, phone_words).
            # tokenize_targets already contains only TOKENIZE-action detections.
            if tokenize_targets:
                masked_prompt, token_map = tokenize(original_prompt, tokenize_targets)
                for label, original_value in token_map.items():
                    encrypted = encrypt(original_value)
                    TokenMap.objects.create(
                        user=request.user,
                        token_label=label[:30],
                        encrypted_value=encrypted,
                    )
            else:
                masked_prompt = original_prompt
                token_map = {}

            processed_prompt = masked_prompt

            # Call AI with the processed (PII-masked or original) prompt
            ai_response = mock_ai(processed_prompt)

            # Log everything — encrypt the original prompt for data-at-rest security
            PromptLog.objects.create(
                user=request.user,
                original_prompt=encrypt(original_prompt),
                processed_prompt=processed_prompt,
                detected_types=detected_types,
                action=action,
                reasons=reasons,
                risk_score=risk_score,
                risk_level=risk_level,
                ai_response=ai_response,
            )

            result = {
                "original_prompt":  original_prompt,
                "processed_prompt": processed_prompt,
                "action":           action,
                "reasons":          reasons,
                "detected_types":   detected_types,
                "risk_score":       risk_score,
                "risk_level":       risk_level,
                "ai_response":      ai_response,
                "block_details":    [],
            }

    return render(request, "firewall/prompt.html", {"result": result})


# ---------------------------------------------------------------------------
# Admin Log Page
# ---------------------------------------------------------------------------
@login_required(login_url="/login/")
def logs_view(request):
    """Display all prompt logs – Admin only."""
    if request.user.role != "ADMIN":
        messages.error(request, "Access denied. Admin privileges required.")
        return redirect("dashboard")

    logs = PromptLog.objects.select_related("user").all()
    return render(request, "firewall/logs.html", {"logs": logs})


# ---------------------------------------------------------------------------
# Log Detail Page
# ---------------------------------------------------------------------------
@login_required(login_url="/login/")
def log_detail_view(request, log_id):
    """Display full details of a single prompt log – Admin only."""
    if request.user.role != "ADMIN":
        messages.error(request, "Access denied. Admin privileges required.")
        return redirect("dashboard")

    log = get_object_or_404(PromptLog.objects.select_related("user"), pk=log_id)
    return render(request, "firewall/log_detail.html", {"log": log})
