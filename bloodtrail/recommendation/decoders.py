"""
Auto-Decoders for BloodTrail Recommendation Engine.

Automatically detect and decode encoded/encrypted values:
- Base64
- Hex
- VNC Password (known DES key)
- AES-CBC (with provided key/IV)
"""

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple, Callable
from enum import Enum, auto


class DecodeMethod(Enum):
    """Methods used to decode values."""
    BASE64 = auto()
    HEX = auto()
    VNC_DES = auto()
    AES_CBC = auto()
    ROT13 = auto()


@dataclass
class DecodeResult:
    """Result of a decode attempt."""
    success: bool
    method: Optional[DecodeMethod] = None
    original: str = ""
    decoded: str = ""
    confidence: float = 0.0
    notes: str = ""


# Known VNC DES key (hardcoded in TightVNC/RealVNC)
VNC_DES_KEY = bytes([0xe8, 0x4a, 0xd6, 0x60, 0xc4, 0x72, 0x1a, 0xe0])


def try_base64(value: str) -> DecodeResult:
    """
    Try to decode a base64 encoded string.

    Returns DecodeResult with success=True if:
    - Value is valid base64
    - Decoded result is printable ASCII
    """
    result = DecodeResult(success=False, original=value, method=DecodeMethod.BASE64)

    # Quick checks
    if not value or len(value) < 4:
        return result

    # Base64 pattern check
    if not re.match(r'^[A-Za-z0-9+/]+=*$', value):
        return result

    try:
        # Add padding if needed
        padded = value + '=' * (4 - len(value) % 4) if len(value) % 4 else value
        decoded_bytes = base64.b64decode(padded)

        # Try to decode as UTF-8/ASCII
        decoded = decoded_bytes.decode('utf-8', errors='strict')

        # Check if result is printable
        if decoded.isprintable() and len(decoded) > 0:
            result.success = True
            result.decoded = decoded
            result.confidence = 0.9 if len(decoded) >= 4 else 0.7
            result.notes = f"Base64 decoded: {len(value)} chars -> {len(decoded)} chars"
            return result

    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass

    return result


def try_hex(value: str) -> DecodeResult:
    """
    Try to decode a hex encoded string.

    Handles formats:
    - Plain hex: 6865786465636f6465
    - With prefix: 0x6865786465636f6465
    - With colons: 68:65:78:64:65:63:6f:64:65
    - Registry style: hex:68,65,78,64,65,63,6f,64,65
    """
    result = DecodeResult(success=False, original=value, method=DecodeMethod.HEX)

    if not value:
        return result

    # Normalize the input
    cleaned = value.lower()

    # Remove common prefixes/formats
    if cleaned.startswith('0x'):
        cleaned = cleaned[2:]
    elif cleaned.startswith('hex:'):
        cleaned = cleaned[4:]

    # Remove separators
    cleaned = re.sub(r'[:\-,\s]', '', cleaned)

    # Validate hex pattern
    if not re.match(r'^[0-9a-f]+$', cleaned):
        return result

    # Must be even length
    if len(cleaned) % 2 != 0:
        return result

    try:
        decoded_bytes = bytes.fromhex(cleaned)
        decoded = decoded_bytes.decode('utf-8', errors='strict')

        if decoded.isprintable() and len(decoded) > 0:
            result.success = True
            result.decoded = decoded
            result.confidence = 0.85
            result.notes = f"Hex decoded: {len(cleaned)} hex chars -> {len(decoded)} chars"
            return result

    except (ValueError, UnicodeDecodeError):
        pass

    return result


def decrypt_vnc_password(encrypted_hex: str) -> DecodeResult:
    """
    Decrypt VNC password encrypted with known DES key.

    VNC stores passwords encrypted with a hardcoded DES key.
    This is the same key used by TightVNC, RealVNC, etc.

    Input formats accepted:
    - hex:6b,cf,2a,4b,6e,5a,ca,0f (registry style)
    - 6bcf2a4b6e5aca0f (plain hex)
    """
    result = DecodeResult(
        success=False,
        original=encrypted_hex,
        method=DecodeMethod.VNC_DES
    )

    if not encrypted_hex:
        return result

    # Normalize hex string
    cleaned = encrypted_hex.lower()
    if cleaned.startswith('hex:'):
        cleaned = cleaned[4:]
    cleaned = re.sub(r'[,:\s]', '', cleaned)

    if not re.match(r'^[0-9a-f]+$', cleaned) or len(cleaned) < 16:
        return result

    try:
        # Import DES here to avoid dependency issues if pycryptodome not installed
        try:
            from Crypto.Cipher import DES
        except ImportError:
            result.notes = "pycryptodome not installed - cannot decrypt VNC password"
            return result

        # VNC uses the first 8 bytes only
        encrypted_bytes = bytes.fromhex(cleaned[:16])

        # Decrypt with known key
        cipher = DES.new(VNC_DES_KEY, DES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)

        # Remove null padding and decode
        decrypted = decrypted_bytes.rstrip(b'\x00').decode('utf-8', errors='ignore')

        if decrypted and len(decrypted) > 0:
            result.success = True
            result.decoded = decrypted
            result.confidence = 0.95
            result.notes = "VNC password decrypted using known DES key"
            return result

    except Exception as e:
        result.notes = f"VNC decrypt failed: {e}"

    return result


def try_aes_cbc(
    encrypted_b64: str,
    key: bytes,
    iv: bytes
) -> DecodeResult:
    """
    Decrypt AES-CBC encrypted value (like Cascade's LDAP password).

    Args:
        encrypted_b64: Base64 encoded ciphertext
        key: AES key (16, 24, or 32 bytes)
        iv: Initialization vector (16 bytes)

    Returns:
        DecodeResult with decrypted value
    """
    result = DecodeResult(
        success=False,
        original=encrypted_b64,
        method=DecodeMethod.AES_CBC
    )

    if not encrypted_b64 or not key or not iv:
        return result

    try:
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
        except ImportError:
            result.notes = "pycryptodome not installed - cannot decrypt AES"
            return result

        # Decode base64 ciphertext
        ciphertext = base64.b64decode(encrypted_b64)

        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = cipher.decrypt(ciphertext)

        # Try to unpad (PKCS7)
        try:
            decrypted_bytes = unpad(decrypted_bytes, AES.block_size)
        except ValueError:
            # No padding or invalid padding - try without
            decrypted_bytes = decrypted_bytes.rstrip(b'\x00')

        decrypted = decrypted_bytes.decode('utf-8', errors='ignore')

        if decrypted and decrypted.isprintable():
            result.success = True
            result.decoded = decrypted
            result.confidence = 0.9
            result.notes = "AES-CBC decrypted successfully"
            return result

    except Exception as e:
        result.notes = f"AES decrypt failed: {e}"

    return result


def extract_vnc_password_from_reg(content: str) -> Optional[str]:
    """
    Extract VNC password hex from .reg file content.

    Looks for patterns like:
    "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
    """
    patterns = [
        r'"Password"=hex:([0-9a-fA-F,]+)',
        r'"PasswordViewOnly"=hex:([0-9a-fA-F,]+)',
        r'Password.*=.*hex:([0-9a-fA-F,]+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def decode_value(value: str, try_all: bool = True) -> DecodeResult:
    """
    Auto-detect and decode an encoded value.

    Tries decoders in order of likelihood:
    1. Base64 (most common for LDAP attributes)
    2. Hex
    3. VNC (if looks like encrypted password)

    Args:
        value: The value to decode
        try_all: If True, try all methods. If False, stop at first success.

    Returns:
        Best DecodeResult (highest confidence success, or first failure)
    """
    if not value:
        return DecodeResult(success=False, original=value, notes="Empty value")

    decoders: List[Tuple[str, Callable]] = [
        ("base64", try_base64),
        ("hex", try_hex),
    ]

    # Check if value looks like VNC password
    if 'hex:' in value.lower() or re.match(r'^[0-9a-f,]{16,}$', value.lower()):
        decoders.append(("vnc", decrypt_vnc_password))

    best_result = DecodeResult(success=False, original=value)

    for name, decoder in decoders:
        result = decoder(value)
        if result.success:
            if result.confidence > best_result.confidence:
                best_result = result
            if not try_all:
                break

    return best_result


def looks_like_password(value: str) -> bool:
    """
    Heuristic check if a decoded value looks like a password.

    Returns True if the value:
    - Is 4-32 characters
    - Contains mix of chars (not all same)
    - Doesn't look like a path, URL, etc.
    """
    if not value or len(value) < 4 or len(value) > 32:
        return False

    # Reject if all same character
    if len(set(value)) == 1:
        return False

    # Reject common non-password patterns
    non_password_patterns = [
        r'^https?://',      # URLs
        r'^[/\\]',          # Paths
        r'^[\w.-]+@',       # Emails
        r'^\d{1,3}\.\d',    # IPs
        r'^\s*$',           # Whitespace
    ]

    for pattern in non_password_patterns:
        if re.match(pattern, value):
            return False

    return True
