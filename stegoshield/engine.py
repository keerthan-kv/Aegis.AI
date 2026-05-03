"""
stegoshield/engine.py – Core steganography engine.

Provides two steganography methods:

1. **Text-based (zero-width Unicode)** — Encodes a secret message into
   cover text using invisible zero-width characters.  The output looks
   identical to the original text but carries hidden data.

2. **File-based (delimiter)** — Encodes a secret message into any file
   by appending it after a delimiter marker.  The file retains its
   original format and the hidden payload is invisible to normal viewers.

Both methods apply XOR obfuscation with a user-supplied passkey before
embedding, adding a lightweight authentication/integrity layer.
"""

from __future__ import annotations

import hashlib

# ── Zero-width characters used for binary encoding ────────────────────────────
_ZW_ZERO = "\u200b"   # ZERO WIDTH SPACE        → binary 0
_ZW_ONE = "\u200c"    # ZERO WIDTH NON-JOINER   → binary 1
_ZW_SEP = "\u200d"    # ZERO WIDTH JOINER       → byte separator
_ZW_START = "\ufeff"  # BOM / ZERO WIDTH NO-BREAK SPACE → start marker

_ZW_CHARS = {_ZW_ZERO, _ZW_ONE, _ZW_SEP, _ZW_START}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _xor_with_key(data: bytes, key: str) -> bytes:
    """XOR each byte of *data* with a repeating cycle of *key* bytes."""
    if not key:
        return data
    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def message_hash(message: str) -> str:
    """Return a SHA-256 hex digest of *message* (for audit logging)."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# TEXT-BASED STEGANOGRAPHY (zero-width Unicode)
# ═══════════════════════════════════════════════════════════════════════════════

def text_encode(cover_text: str, secret_message: str, passkey: str = "") -> str:
    """
    Embed *secret_message* into *cover_text* using zero-width Unicode chars.

    The encoded payload is inserted after the first character of the cover
    text so that the result displays identically to the original.

    Args:
        cover_text:      Visible carrier text.
        secret_message:  The message to hide.
        passkey:         Optional passkey for XOR obfuscation.

    Returns:
        Cover text with the hidden payload embedded.
    """
    if not cover_text:
        raise ValueError("Cover text must not be empty.")
    if not secret_message:
        raise ValueError("Secret message must not be empty.")

    # XOR-obfuscate, then encode each byte as 8 zero-width chars
    raw = secret_message.encode("utf-8")
    obfuscated = _xor_with_key(raw, passkey)

    zw_payload = _ZW_START
    for i, byte_val in enumerate(obfuscated):
        if i > 0:
            zw_payload += _ZW_SEP
        for bit in range(7, -1, -1):
            zw_payload += _ZW_ONE if (byte_val >> bit) & 1 else _ZW_ZERO

    # Insert after first character
    return cover_text[0] + zw_payload + cover_text[1:]


def text_decode(stego_text: str, passkey: str = "") -> str:
    """
    Extract a hidden message from *stego_text*.

    Args:
        stego_text: Text containing zero-width encoded payload.
        passkey:    The same passkey used during encoding.

    Returns:
        The decoded secret message.

    Raises:
        ValueError: If no hidden payload is found or decoding fails.
    """
    # Find the start marker
    start_idx = stego_text.find(_ZW_START)
    if start_idx == -1:
        raise ValueError("No hidden message found in the provided text.")

    # Extract all zero-width characters after the marker
    zw_chars = []
    for ch in stego_text[start_idx + 1:]:
        if ch in _ZW_CHARS:
            zw_chars.append(ch)
        elif zw_chars:
            # We've passed through the payload region
            break

    if not zw_chars:
        raise ValueError("No hidden message found in the provided text.")

    # Split by separator to get byte groups
    byte_groups: list[list[str]] = [[]]
    for ch in zw_chars:
        if ch == _ZW_SEP:
            byte_groups.append([])
        elif ch in (_ZW_ZERO, _ZW_ONE):
            byte_groups[-1].append(ch)

    # Convert to bytes
    result_bytes = bytearray()
    for group in byte_groups:
        if len(group) != 8:
            continue
        byte_val = 0
        for bit_char in group:
            byte_val = (byte_val << 1) | (1 if bit_char == _ZW_ONE else 0)
        result_bytes.append(byte_val)

    if not result_bytes:
        raise ValueError("Failed to decode hidden message.")

    # Reverse XOR
    decoded = _xor_with_key(bytes(result_bytes), passkey)

    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "Decoding failed — wrong passkey or corrupted payload."
        )

# ═══════════════════════════════════════════════════════════════════════════════
# FILE-BASED STEGANOGRAPHY (delimiter approach – from Stego/app.py)
# ═══════════════════════════════════════════════════════════════════════════════

_FILE_DELIM = b"<<STEGO_DELIM>>"


def file_encode(cover_bytes: bytes, secret_message: str, passkey: str = "") -> bytes:
    """
    Embed *secret_message* into a cover file using a delimiter-based approach.

    The secret message is XOR-obfuscated with the passkey and appended to
    the cover file bytes using ``<<STEGO_DELIM>>`` markers.  The output
    file retains the original format and can be opened normally — the
    hidden payload sits after the file's logical end.

    Args:
        cover_bytes:     Raw bytes of any cover file (image, PDF, doc, etc.).
        secret_message:  The message to hide.
        passkey:         Optional passkey for XOR obfuscation.

    Returns:
        Bytes of the stego file with the hidden message appended.
    """
    if not cover_bytes:
        raise ValueError("Cover file must not be empty.")
    if not secret_message:
        raise ValueError("Secret message must not be empty.")

    raw = secret_message.encode("utf-8")
    obfuscated = _xor_with_key(raw, passkey)

    # Format: cover_bytes + DELIM + obfuscated_message
    return cover_bytes + _FILE_DELIM + obfuscated


def file_decode(stego_bytes: bytes, passkey: str = "") -> str:
    """
    Extract a hidden message from a stego file.

    Args:
        stego_bytes: Raw bytes of the stego file.
        passkey:     The same passkey used during encoding.

    Returns:
        The decoded secret message.

    Raises:
        ValueError: If no hidden message is found or decoding fails.
    """
    if _FILE_DELIM not in stego_bytes:
        raise ValueError("No hidden message found in this file.")

    # Everything after the last delimiter is the obfuscated message
    parts = stego_bytes.rsplit(_FILE_DELIM, 1)
    if len(parts) < 2 or not parts[1]:
        raise ValueError("No hidden message found in this file.")

    obfuscated = parts[1]
    decoded_bytes = _xor_with_key(obfuscated, passkey)

    try:
        return decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "Decoding failed — wrong passkey or corrupted payload."
        )

