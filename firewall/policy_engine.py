"""
firewall/policy_engine.py
=========================
Zero Trust Policy Engine for Aegis.AI

Two-Tier Risk Model:
─────────────────────────────────────────────────────────────────────────────
🟡 PERSONAL PII (Mask) — identity data, value is obscured but prompt not blocked:
   email, phone, aadhaar, phone_words

🔴 HIGH / CRITICAL RISK (Block) — dangerous content, denied entirely for ALL roles:
   api_key, cloud_key, source_code, credit_card, ssn, financial_account, password,
   private_key, encryption_key, secret_token, encoded_payload,
   adversarial_injection, credential_request, embedded_secret_key,
   social_engineering_injection

─────────────────────────────────────────────────────────────────────────────
ALL ROLES (Admin, Employee, Intern):
  Normal text           → ALLOW
  Personal PII          → MASK  (email, phone, aadhaar only)
  ANY API Key format    → BLOCK (HIGH RISK — all roles, all formats)
  Source Code           → BLOCK (HIGH RISK — all roles)
  High/Critical data    → BLOCK (cloud keys, private keys, credit cards, etc.)

─────────────────────────────────────────────────────────────────────────────

Priority order inside evaluate_policy():
  1. UNIVERSAL_BLOCK     → always BLOCK
  2. Role BLOCK list     → BLOCK for role-specific rules
  3. UNIVERSAL_TOKENIZE  → always MASK (personal PII + phone_words)
  4. Role TOKENIZE list  → MASK for role-specific rules
  5. Role ALLOW list     → explicitly permitted
  6. Default             → TOKENIZE (zero-trust fail-safe)
"""

from __future__ import annotations
from typing import TYPE_CHECKING, FrozenSet, Dict, List
from dataclasses import dataclass

if TYPE_CHECKING:
    from .scanner import Detection

# ---------------------------------------------------------------------------
# Action constants
# ---------------------------------------------------------------------------
ALLOW    = "ALLOW"
BLOCK    = "BLOCK"
TOKENIZE = "TOKENIZE"

# ---------------------------------------------------------------------------
# Universal rules — apply to ALL roles, cannot be overridden.
# ---------------------------------------------------------------------------

# 🔴 HIGH / CRITICAL RISK — blocked for every role, no exceptions
UNIVERSAL_BLOCK: FrozenSet[str] = frozenset({
    # API keys — ALL formats blocked universally (HIGH RISK)
    "api_key",               # All API key formats: simple, prefixed, JWT, OAuth, UUID, Base64, GitHub
    # Cloud / production credentials
    "cloud_key",             # AWS AKIA access keys, cloud secrets (HIGH RISK)
    # Source code — blocked for all roles
    "source_code",           # Python / JS / PHP / SQL-shell code patterns
    # Cryptographic material
    "private_key",           # RSA/EC/DSA private keys (BEGIN PRIVATE KEY)
    "encryption_key",        # PEM key headers incl. public key
    # Financial / identity
    "credit_card",           # Credit card numbers (CRITICAL)
    "ssn",                   # US Social Security Number (CRITICAL)
    "financial_account",     # Bank / account numbers
    # Passwords / secrets
    "password",              # Database root passwords, credentials
    "secret_token",          # Master admin tokens / auth credentials
    # Adversarial
    "adversarial_injection", # Jailbreak / prompt injection
    "encoded_payload",       # Base64 / hex obfuscated instructions
    "embedded_secret_key",   # Secrets hidden in prompts (e.g. "secret key: rpUnff")
    "social_engineering_injection", # PWNED-style: phrase redefinition + forced output + 'ignore rules'
    # Social engineering
    "credential_request",    # "Give me admin credentials" prompts
})

# 🟡 PERSONAL PII — always masked for every role (never blocked)
UNIVERSAL_TOKENIZE: FrozenSet[str] = frozenset({
    "email",       # Personal email address
    "phone",       # Personal phone number
    "aadhaar",     # Indian national ID (12-digit personal ID)
    "phone_words", # Phone numbers spoken as digit words
    "mac_address", # MAC Address
    "ip_address",  # IP Address (IPv4/IPv6)
    "passport",    # Passport number
})

# ---------------------------------------------------------------------------
# Role-specific policy rule tables
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RolePolicy:
    block:    FrozenSet[str]
    tokenize: FrozenSet[str]
    allow:    FrozenSet[str]


ROLE_POLICIES: Dict[str, RolePolicy] = {

    # ------------------------------------------------------------------
    # ADMIN — personal PII masked universally; high-risk content blocked.
    # sql_query and documentation permitted for admin workflows.
    # ------------------------------------------------------------------
    "ADMIN": RolePolicy(
        block=frozenset(),    # All high/critical types handled by UNIVERSAL_BLOCK
        tokenize=frozenset(), # Personal PII handled by UNIVERSAL_TOKENIZE
        allow=frozenset({
            "documentation", # Internal docs allowed
            "sql_query",     # SQL allowed for admin workflows
        }),
    ),

    # ------------------------------------------------------------------
    # EMPLOYEE — personal PII masked universally; technical content blocked.
    # ------------------------------------------------------------------
    "EMPLOYEE": RolePolicy(
        block=frozenset({
            "sql_query",
        }),
        tokenize=frozenset(), # Personal PII handled by UNIVERSAL_TOKENIZE
        allow=frozenset(),
    ),

    # ------------------------------------------------------------------
    # INTERN — Zero Trust / Strictest Mode.
    # Personal PII masked universally; all technical/credential content blocked.
    # ------------------------------------------------------------------
    "INTERN": RolePolicy(
        block=frozenset({
            "documentation",
            "sql_query",
        }),
        tokenize=frozenset(), # Personal PII handled by UNIVERSAL_TOKENIZE
        allow=frozenset(),
    ),
}

# ---------------------------------------------------------------------------
# Human-readable reason templates
# ---------------------------------------------------------------------------
_REASON_TEMPLATES: Dict[str, str] = {
    "universal_block":    "⛔ {dtype} is universally blocked — HIGH/CRITICAL risk under Zero Trust policy.",
    "role_block":         "🚫 {dtype} is blocked for {role} role.",
    "universal_tokenize": "🔒 {dtype} is universally masked (applies to all roles).",
    "role_tokenize":      "🔐 {dtype} will be masked for {role} role.",
    "allow":              "✅ {dtype} is permitted for {role} role.",
    "default_tokenize":   "⚠️  Unknown data type '{dtype}' – masked by default (Zero Trust fail-safe).",
}

# ---------------------------------------------------------------------------
# Per-dtype block explanations shown in the UI when a prompt is BLOCKED
# ---------------------------------------------------------------------------
BLOCK_DTYPE_REASONS: Dict[str, str] = {
    "api_key":               "API keys grant programmatic access to services. Exposing them can lead to unauthorized access, data breaches, and financial damage.",
    "cloud_key":             "Cloud credentials (e.g. AWS AKIA keys) provide access to cloud infrastructure. Leaking these can result in full account takeover and massive data loss.",
    "credit_card":           "Credit card numbers are highly sensitive financial data. Transmitting them through AI systems violates PCI-DSS compliance and enables fraud.",
    "financial_account":     "Bank account and IBAN numbers are protected financial identifiers. Sharing them exposes individuals to unauthorized withdrawals and financial fraud.",
    "password":              "Passwords are primary authentication credentials. Sharing them in plaintext is a critical security violation that can compromise entire systems.",
    "private_key":           "Private cryptographic keys are the foundation of secure communications. Exposure immediately undermines all encryption protecting your systems.",
    "encryption_key":        "Encryption key material (PEM headers) is extremely sensitive — leaking it renders all encrypted data vulnerable to decryption.",
    "secret_token":          "Secret tokens (auth/session tokens) act like passwords for APIs and services. Exposure can allow full impersonation of legitimate users.",
    "ssn":                   "US Social Security Numbers are government-issued identity credentials. Exposure can lead to identity theft and legal liability.",
    "adversarial_injection": "This prompt contains jailbreak or prompt-injection patterns designed to override AI safety controls. Such attempts are blocked under Zero Trust policy.",
    "encoded_payload":       "Base64 or hex-encoded blobs may contain obfuscated malicious instructions. These are blocked to prevent payload smuggling through the firewall.",
    "credential_request":    "This prompt appears to be requesting credentials, passwords, or sensitive account details — a social engineering vector blocked by policy.",
    "source_code":           "Source code may contain logic, secrets, or intellectual property. Submitting code to AI systems creates data exfiltration and IP risks.",
    "sql_query":             "SQL statements can expose or manipulate database structure and data. Blocked to prevent SQL injection vectors and unauthorized data access.",
    "embedded_secret_key":   "This prompt embeds a secret key or token using natural-language framing (e.g. 'Remember this secret key: rpUnff'). This is a known adversarial technique to smuggle credentials past AI filters. Blocked under Zero Trust policy.",
    "social_engineering_injection": "This prompt uses social engineering injection techniques: redefining phrases, forcing specific outputs, embedding 'ignore these rules' directives, or using story-wrapper frames to smuggle malicious instructions. This is a multi-vector adversarial attack pattern (e.g. PWNED-style attacks) and is blocked under Zero Trust policy.",
}


def _fmt(template_key: str, dtype: str, role: str = "") -> str:
    return _REASON_TEMPLATES[template_key].format(
        dtype=dtype.replace("_", " ").title(),
        role=role,
    )


# ---------------------------------------------------------------------------
# Core evaluation function
# ---------------------------------------------------------------------------

def evaluate_policy(role: str, dtype: str) -> tuple[str, str]:
    """
    Evaluate the policy action for a single detected data type and user role.

    Returns:
        (action, reason) — action is ALLOW | BLOCK | TOKENIZE.
    """
    role_policy = ROLE_POLICIES.get(role)

    if dtype in UNIVERSAL_BLOCK:
        return BLOCK, _fmt("universal_block", dtype)

    if role_policy and dtype in role_policy.block:
        return BLOCK, _fmt("role_block", dtype, role)

    if dtype in UNIVERSAL_TOKENIZE:
        return TOKENIZE, _fmt("universal_tokenize", dtype)

    if role_policy and dtype in role_policy.tokenize:
        return TOKENIZE, _fmt("role_tokenize", dtype, role)

    if role_policy and dtype in role_policy.allow:
        return ALLOW, _fmt("allow", dtype, role)

    return TOKENIZE, _fmt("default_tokenize", dtype)


# ---------------------------------------------------------------------------
# Aggregation function
# ---------------------------------------------------------------------------

def apply_policy(role: str, detections: List[Detection]) -> dict:
    """
    Aggregate all detection policies into a single firewall decision.
    BLOCK wins over TOKENIZE wins over ALLOW.
    """
    if not detections:
        return {"action": ALLOW, "reasons": [], "tokenize_targets": []}

    reasons: List[str] = []
    tokenize_targets: List[Detection] = []
    has_block = False
    seen_dtypes: set = set()

    for detection in detections:
        action, reason = evaluate_policy(role, detection.dtype)
        # Only add a reason the first time this dtype is encountered —
        # avoids repeating the same policy decision for duplicate matches.
        if detection.dtype not in seen_dtypes:
            seen_dtypes.add(detection.dtype)
            reasons.append(reason)
        if action == BLOCK:
            has_block = True
        elif action == TOKENIZE:
            tokenize_targets.append(detection)

    final_action = BLOCK if has_block else (TOKENIZE if tokenize_targets else ALLOW)

    return {
        "action": final_action,
        "reasons": reasons,
        "tokenize_targets": tokenize_targets,
    }
