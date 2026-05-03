"""
firewall/risk_scorer.py
=======================
Risk Scoring Engine for Aegis.AI — Spec-Compliant Percentage System.

Risk Percentage per Data Type (spec):
  Email               → 40%
  Phone / Phone Words → 45%
  Simple API Key      → 75%
  Prefixed API Key    → 85%   (api_key uses the higher value — prefixed covers both)
  JWT / OAuth Token   → 80%
  Cloud Access Key    → 90%
  Cloud Secret Key    → 95%
  HMAC Credential     → 85%
  Credit Card         → 95%
  Government ID       → 95%   (SSN / Aadhaar)
  Private Key         → 100%
  Encryption Key      → 100%  (public key PEM is still sensitive key material)
  Password            → 90%
  Financial Account   → 80%
  Secret Token        → 85%
  Encoded Payload     → 80%
  Adversarial         → 70%
  Credential Request  → 70%

Overall risk = MAX of all detected dtype risk values (not additive).

Risk Levels:
   0–20%  → LOW
  21–40%  → MODERATE
  41–60%  → HIGH
  61–80%  → SEVERE
  81–100% → CRITICAL

Threshold Enforcement:
  If risk_score >= 60 → flag should_block = True (used to escalate policy).
"""

from __future__ import annotations
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .scanner import Detection

from .policy_engine import evaluate_policy, BLOCK

# ---------------------------------------------------------------------------
# Risk percentage per detection type (spec-defined)
# ---------------------------------------------------------------------------

_DTYPE_RISK_PCT: dict[str, int] = {
    # PII — Contact
    "email":             40,
    "phone":             45,
    "phone_words":       45,   # Spoken phone numbers — same risk as numeric phone
    # 🟡 Basic Risk API Credentials (Mask)
    "api_key":           85,   # Simple / Prefixed / JWT / OAuth / UUID / Base64 / HMAC
    "secret_token":      85,   # Master admin / auth tokens
    # 🔴 High / Critical Risk (Block)
    "cloud_key":         95,   # AWS AKIA access keys, cloud secrets w/ slashes
    "credit_card":       95,
    "financial_account": 80,
    "ssn":               95,
    "aadhaar":           95,
    "password":          90,
    "credential_request": 70,
    "encryption_key":    100,
    "private_key":       100,
    # Adversarial / obfuscated
    "adversarial_injection": 70,
    "encoded_payload":   80,
    # Technical content
    "source_code":       30,
    "sql_query":         40,
    "documentation":     20,
}

_DEFAULT_RISK_PCT = 30   # Fallback for unknown types
_RISK_THRESHOLD_BLOCK = 60  # Flag should_block when score >= 60%

# ---------------------------------------------------------------------------
# Risk level classification
# ---------------------------------------------------------------------------

_RISK_LEVELS = [
    (20,  "LOW"),
    (40,  "MODERATE"),
    (60,  "HIGH"),
    (80,  "SEVERE"),
    (100, "CRITICAL"),
]


def classify_risk(score: int) -> str:
    """Return risk level label for a given numeric score."""
    for threshold, label in _RISK_LEVELS:
        if score <= threshold:
            return label
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Main risk calculation function
# ---------------------------------------------------------------------------

def calculate_risk(role: str, detections: List["Detection"]) -> dict:
    """
    Calculate the aggregate risk score for a prompt.

    Logic: Overall risk = MAX of all detected dtype risk percentages.
    If any dtype is explicitly BLOCKED by the role policy, that dtype's
    risk is boosted to at least 75% (blocked = highly sensitive in context).

    Args:
        role       : User role string — "ADMIN", "EMPLOYEE", or "INTERN".
        detections : List of Detection objects from scanner.scan().

    Returns:
        {
            "score":        int,   # 0–100
            "level":        str,   # LOW / MODERATE / HIGH / SEVERE / CRITICAL
            "should_block": bool,  # True if score >= RISK_THRESHOLD_BLOCK
        }
    """
    if not detections:
        return {"score": 0, "level": "LOW", "should_block": False}

    max_score = 0

    for detection in detections:
        base_pct = _DTYPE_RISK_PCT.get(detection.dtype, _DEFAULT_RISK_PCT)

        # If this dtype is blocked for the current role, treat it as at least 75%
        action, _ = evaluate_policy(role, detection.dtype)
        if action == BLOCK:
            base_pct = max(base_pct, 75)

        if base_pct > max_score:
            max_score = base_pct

    score = min(max_score, 100)
    level = classify_risk(score)
    should_block = score >= _RISK_THRESHOLD_BLOCK

    return {
        "score":        score,
        "level":        level,
        "should_block": should_block,
    }
