"""
tokenization.py – Replace sensitive spans with partial-exposure masks.

Masking format (spec):
    Show first 3 characters + ******** + last 3 characters.

Examples:
    sk_prod_8xYzLmNpQrT4vW9aBcD3eFgH  →  sk_**********************egH
    john.doe@company.com               →  joh***************com
    9876543210                         →  987****210
    4111111111111111                   →  411**********111

Edge cases:
  - len <= 3  → all asterisks
  - len 4–6   → first char + asterisks (no full suffix to expose)
"""

from typing import List, Dict, Tuple
from .scanner import Detection


def _partial_mask(value: str) -> str:
    """
    Apply partial-exposure masking: first 3 + '********' + last 3.

    Edge cases:
      - len <= 3  → all asterisks (nothing to expose safely)
      - len 4–6   → first char + asterisks (suffix would overlap prefix)
    """
    n = len(value)
    if n <= 3:
        return "*" * n
    if n <= 6:
        # Show only the first character to avoid exposing too much
        return value[0] + "*" * (n - 1)
    # Standard: first 3 + middle masked + last 3
    return value[:3] + "*" * (n - 6) + value[-3:]


def tokenize(prompt: str, targets: List[Detection]) -> Tuple[str, Dict[str, str]]:
    """
    Replace each detection in *targets* with a partial-exposure mask.

    Handles overlapping spans by working right-to-left through the string
    so earlier indices stay valid.

    Returns:
        processed_prompt : str  – prompt with sensitive values partially masked
        token_map        : dict – {masked_label: original_value} for audit storage
    """
    if not targets:
        return prompt, {}

    # Deduplicate by (start, end) — keep first occurrence per span
    seen: set = set()
    unique_targets: List[Detection] = []
    for d in targets:
        key = (d.start, d.end)
        if key not in seen:
            seen.add(key)
            unique_targets.append(d)

    # Sort ascending by start position to process left-to-right for label assignment
    unique_targets.sort(key=lambda d: d.start)

    # Build ordered list of (start, end, mask_label, original_value)
    # Track used mask labels to avoid collisions (same value appearing twice)
    used_labels: Dict[str, int] = {}
    ordered: List[tuple] = []

    for detection in unique_targets:
        mask = _partial_mask(detection.value)
        # Deduplicate mask labels if the same mask appears more than once
        if mask in used_labels:
            used_labels[mask] += 1
            label = f"{mask}[{used_labels[mask]}]"
        else:
            used_labels[mask] = 1
            label = mask
        ordered.append((detection.start, detection.end, label, detection.value))

    token_map: Dict[str, str] = {}
    result = prompt

    # Apply replacements right-to-left so indices stay valid
    for start, end, label, original_value in reversed(ordered):
        token_map[label] = original_value
        result = result[:start] + label + result[end:]

    return result, token_map
