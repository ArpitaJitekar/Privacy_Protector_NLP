"""
Regular expression rules and validation logic for structured personal data.
Defines PII categories, regex patterns, validation hooks, and base risk classifications.
"""

from dataclasses import dataclass
from typing import Callable, Optional, Pattern
import re


@dataclass
class PatternDefinition:
    category: str
    pattern: Pattern
    base_risk: str            # "Low", "Medium", "High", "Critical"
    base_weight: int          # 1 to 10
    reason: str
    recommendation: str
    validator: Optional[Callable[[str], bool]] = None


def luhn_checksum(card_number: str) -> bool:
    """Validates credit card numbers using the standard Luhn algorithm."""
    clean = re.sub(r"\D", "", card_number)
    if not 13 <= len(clean) <= 19:
        return False
    digits = [int(d) for d in clean]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def valid_ipv4(ip: str) -> bool:
    """Validates IPv4 octets (0-255) and excludes non-sensitive ones (0.0.0.0, 127.0.0.1, 255.255.255.255)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
        if not all(0 <= o <= 255 for o in octets):
            return False
        # Filter out common placeholders
        if octets == [0, 0, 0, 0] or octets == [255, 255, 255, 255] or octets == [127, 0, 0, 1]:
            return False
        return True
    except ValueError:
        return False


def valid_ssn(ssn: str) -> bool:
    """Validates US SSN basic rules (not 000, 666, or 900-999 in first group)."""
    clean = re.sub(r"\D", "", ssn)
    if len(clean) != 9:
        return False
    area = int(clean[:3])
    group = int(clean[3:5])
    serial = int(clean[5:])
    if area == 0 or area == 666 or (900 <= area <= 999):
        return False
    if group == 0 or serial == 0:
        return False
    # Exclude sequential or repeated test strings (e.g. 123456789, 000000000)
    if clean in ("123456789", "987654321", "111111111", "222222222"):
        return False
    return True


def valid_aadhaar(aadhaar: str) -> bool:
    """Validates Indian Aadhaar format (12 digits, cannot begin with 0 or 1)."""
    clean = re.sub(r"\s", "", aadhaar)
    if len(clean) != 12:
        return False
    if clean[0] in ("0", "1"):
        return False
    # Avoid repeating dummy numbers
    if len(set(clean)) <= 2:
        return False
    return True


def valid_phone(phone: str) -> bool:
    """Validates minimum and maximum digit counts for realistic phone numbers."""
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 7 or len(digits) > 15:
        return False
    # Avoid all identical digits
    if len(set(digits)) == 1:
        return False
    return True


# Compile standard PII regex patterns
REGEX_PATTERNS = [
    # 1. Email Addresses
    PatternDefinition(
        category="Email Address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        base_risk="Medium",
        base_weight=4,
        reason="Direct contact identifier that can be used for phishing, social engineering, or spam.",
        recommendation="Mask username (e.g. j***e@domain.com) or replace with general role alias (e.g. contact@domain.com)."
    ),

    # 2. Credit / Debit Card Numbers (with Luhn check)
    PatternDefinition(
        category="Payment Card Number",
        pattern=re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"),
        base_risk="Critical",
        base_weight=9,
        reason="Direct financial credential that can facilitate unauthorized financial transactions.",
        recommendation="Truncate or mask to display only last 4 digits (e.g. **** **** **** 1234) under PCI-DSS standards.",
        validator=luhn_checksum
    ),
    PatternDefinition(
        category="Payment Card Number",
        pattern=re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b"),
        base_risk="Critical",
        base_weight=9,
        reason="Structured 16-digit payment card format.",
        recommendation="Redact full card number immediately and purge from non-PCI compliant storage.",
        validator=luhn_checksum
    ),

    # 3. Government IDs - US Social Security Number (SSN)
    PatternDefinition(
        category="Government ID (SSN)",
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        base_risk="High",
        base_weight=8,
        reason="Primary personal identification number vulnerable to identity theft.",
        recommendation="Mask full identifier or retain only the last 4 digits (e.g. XXX-XX-1234) for verification.",
        validator=valid_ssn
    ),

    # 4. Government IDs - Indian PAN Card
    PatternDefinition(
        category="Government ID (PAN)",
        pattern=re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        base_risk="High",
        base_weight=7,
        reason="Permanent Account Number used for tax identification and financial KYC in India.",
        recommendation="Mask the first 6 characters (e.g. XXXXX1234A) or fully redact in public documents."
    ),

    # 5. Government IDs - Indian Aadhaar Number
    PatternDefinition(
        category="Government ID (Aadhaar)",
        pattern=re.compile(r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b"),
        base_risk="High",
        base_weight=8,
        reason="12-digit Indian national biometric identification number.",
        recommendation="Use Masked Aadhaar displaying only last 4 digits (e.g. XXXX XXXX 1234) as mandated by UIDAI.",
        validator=valid_aadhaar
    ),

    # 6. Phone Numbers (International & Domestic formats)
    PatternDefinition(
        category="Phone Number",
        pattern=re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,5}\b"),
        base_risk="Medium",
        base_weight=4,
        reason="Direct telephone communication channel subject to unsolicited calls, SMS spam, or SIM swap.",
        recommendation="Mask intermediate digits (e.g. 98******10) or provide organizational contact channels.",
        validator=valid_phone
    ),

    # 7. Indian 10-digit Mobile Numbers starting with 6, 7, 8, or 9
    PatternDefinition(
        category="Phone Number",
        pattern=re.compile(r"\b(?:\+91[-.\s]?)?[6-9]\d{9}\b"),
        base_risk="Medium",
        base_weight=4,
        reason="Direct mobile subscriber number.",
        recommendation="Mask digits leaving only the first 2 and last 2 digits visible.",
        validator=valid_phone
    ),

    # 8. IPv4 Addresses
    PatternDefinition(
        category="IP Address",
        pattern=re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        base_risk="Low",
        base_weight=2,
        reason="Host device address indicating internal network topology or user geographical origin.",
        recommendation="Mask host octets (e.g. 192.168.***.***) or replace with sanitized sample addresses.",
        validator=valid_ipv4
    ),

    # 9. Passport Numbers (alphanumeric pattern with prefix)
    PatternDefinition(
        category="Passport Number",
        pattern=re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"),
        base_risk="High",
        base_weight=8,
        reason="International travel and government identity document number.",
        recommendation="Redact fully unless required for immigration compliance; use confidential storage."
    ),

    # 10. Potential Secrets / API Keys / Bearer Tokens
    PatternDefinition(
        category="Cryptographic Key / Secret Token",
        pattern=re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z-_]{35}|sk_live_[0-9a-zA-Z]{24,}|ey[A-Za-z0-9_-]{20,}\.ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b"),
        base_risk="Critical",
        base_weight=10,
        reason="Live machine-to-machine authentication credential granting unauthorized access to external systems.",
        recommendation="Immediately revoke/rotate the compromised secret and configure secrets scanning in CI/CD."
    ),
]
