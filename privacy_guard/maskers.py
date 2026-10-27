"""
Masking and redaction utilities for sensitive PII.
Supports partial redaction to maintain auditability while preventing exposure.
"""

import re


def mask_email(email: str) -> str:
    """Mask email: john.doe@example.com -> j***e@example.com or r***@gmail.com."""
    try:
        parts = email.split("@")
        if len(parts) != 2:
            return "******@masked.com"
        username, domain = parts
        if len(username) <= 2:
            masked_user = username[0] + "***"
        else:
            masked_user = username[0] + "***" + (username[-1] if len(username) > 3 else "")
        return f"{masked_user}@{domain}"
    except Exception:
        return "******@masked.com"


def mask_phone(phone: str) -> str:
    """Mask phone: 9876543210 -> 98******10, +1 (555) 123-4567 -> +1 555-***-4567."""
    clean_digits = re.sub(r"\D", "", phone)
    if len(clean_digits) >= 10:
        prefix = clean_digits[:2]
        suffix = clean_digits[-2:]
        masked_middle = "*" * (len(clean_digits) - 4)
        return f"{prefix}{masked_middle}{suffix}"
    elif len(clean_digits) >= 7:
        prefix = clean_digits[:2]
        suffix = clean_digits[-2:]
        return f"{prefix}***{suffix}"
    return "******"


def mask_id(id_val: str, show_last_digits: int = 4) -> str:
    """Mask IDs (Aadhaar, SSN, PAN, Passport, etc.): 'Value masked for privacy' or 'XXXX-XXXX-1234'."""
    clean = re.sub(r"[\s\-]", "", id_val)
    if len(clean) > show_last_digits:
        last_chars = clean[-show_last_digits:]
        return f"Value masked for privacy (ends in {last_chars})"
    return "Value masked for privacy"


def mask_credit_card(card: str) -> str:
    """Mask credit card: 4111 1111 1111 1234 -> **** **** **** 1234."""
    digits = re.sub(r"\D", "", card)
    if len(digits) >= 13:
        last4 = digits[-4:]
        return f"**** **** **** {last4}"
    return "**** **** **** ****"


def mask_ip(ip: str) -> str:
    """Mask IP: 192.168.1.50 -> 192.168.***.***."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    return "ip.masked.***"


def mask_value(category: str, raw_val: str) -> str:
    """Dispatches appropriate masking strategy based on category."""
    cat_lower = category.lower()
    if "email" in cat_lower:
        return mask_email(raw_val)
    elif "phone" in cat_lower:
        return mask_phone(raw_val)
    elif "credit card" in cat_lower or "card" in cat_lower or "financial" in cat_lower:
        return mask_credit_card(raw_val)
    elif any(kw in cat_lower for kw in ["id", "aadhaar", "pan", "ssn", "passport", "tax", "license"]):
        return mask_id(raw_val)
    elif any(kw in cat_lower for kw in ["secret", "key", "token"]):
        return "Value masked for privacy (Cryptographic Secret)"
    elif "ip" in cat_lower:
        return mask_ip(raw_val)
    else:
        # Fallback masking
        if len(raw_val) <= 4:
            return "***"
        return raw_val[:1] + ("*" * (len(raw_val) - 2)) + raw_val[-1:]
