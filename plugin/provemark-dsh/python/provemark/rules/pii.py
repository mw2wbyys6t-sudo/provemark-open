from __future__ import annotations

import re

EMAIL = re.compile(
    r"(?<![\w.+-])([A-Za-z0-9._%+-]{2,64})@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![\w.-])"
)
LOG_CALL = re.compile(
    r"(?i)\b(console\.(log|info|warn|error|debug)|print|printf|println|"
    r"logger?\.(info|warn|warning|error|debug|exception)|log\.(info|warn|error|debug)|"
    r"System\.out\.print\w*|fmt\.Print\w*)\s*\("
)
SENSITIVE_NAME = re.compile(
    r"(?i)\b(email|e_mail|phone|mobile|tel|nric|ic_no|icno|mykad|nik|ktp|"
    r"philsys|psn|umid|sss|gsis|philhealth|tin|passport|address)\b"
)
PHONE_CANDIDATE = re.compile(
    r"(?<![\d])(\+\d[\d\s().-]{6,17}\d|0\d[\d\s().-]{5,14}\d)(?![\d])"
)
SG_NRIC = re.compile(r"\b([STFGM])(\d{7})([A-Z])\b")
DIGITS_13 = re.compile(r"(?<!\d)(\d{13})(?!\d)")
DIGITS_16 = re.compile(r"(?<!\d)(\d{16})(?!\d)")
DIGITS_12 = re.compile(r"(?<!\d)(\d{12})(?!\d)")
CARD = re.compile(r"(?<![\d])((?:\d[ -]?){12,18}\d)(?![\d])")
PHILSYS_HINT = re.compile(r"(?i)\b(philsys|psn|umid|philippine identification)\b")
NIK_HINT = re.compile(r"(?i)\b(nik|ktp|nomor induk|indonesia)\b")

PLACEHOLDER_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.local",
    "localhost",
    "invalid",
    "domain.com",
    "email.com",
    "company.com",
    "yourcompany.com",
)
PLACEHOLDER_LOCALS = (
    "user",
    "test",
    "foo",
    "bar",
    "your",
    "yourname",
    "name",
    "email",
    "someone",
    "noreply",
    "no-reply",
    "donotreply",
    "admin",
    "hello",
)
TEST_CARDS = {
    "4111111111111111",
    "4242424242424242",
    "4000056655665556",
    "5555555555554444",
    "5200828282828210",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "30569309025904",
    "3530111333300000",
}
SG_WEIGHTS = (2, 7, 6, 5, 4, 3, 2)
SG_TABLES = {
    "S": ("JZIHGFEDCBA", 0),
    "T": ("JZIHGFEDCBA", 0),
    "F": ("XWUTRQPNMLK", 4),
    "G": ("XWUTRQPNMLK", 4),
    "M": ("KLJNPQRTUWX", 3),
}

JURISDICTIONS = ("sg-pdpa", "th-pdpa", "id-pdp", "my-pdpa", "ph-dpa")


def is_placeholder_email(local: str, domain: str) -> bool:
    lowered = domain.lower()
    if any(lowered == item or lowered.endswith("." + item) for item in PLACEHOLDER_DOMAINS):
        return True
    if lowered.endswith((".test", ".invalid", ".local", ".example")):
        return True
    return local.lower() in PLACEHOLDER_LOCALS


def mask_email(local: str, domain: str) -> str:
    return f"{local[0]}***@{domain}"


def mask_tail(digits: str, keep: int = 4) -> str:
    return "*" * max(1, len(digits) - keep) + digits[-keep:]


def mask_card(digits: str) -> str:
    return "**** **** **** " + digits[-4:]


def luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def card_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if not 13 <= len(digits) <= 19:
        return False
    if digits[0] not in "3456":
        return False
    return luhn_ok(digits)


def sg_nric_ok(prefix: str, digits: str, check: str) -> bool:
    table, offset = SG_TABLES[prefix]
    total = sum(int(char) * weight for char, weight in zip(digits, SG_WEIGHTS))
    return table[(total + offset) % 11] == check


def th_id_ok(digits: str) -> bool:
    total = sum(int(digits[index]) * (13 - index) for index in range(12))
    return (11 - total % 11) % 10 == int(digits[12])


def nik_ok(digits: str) -> bool:
    province = int(digits[:2])
    day = int(digits[6:8])
    month = int(digits[8:10])
    if day > 40:
        day -= 40
    return 11 <= province <= 94 and 1 <= day <= 31 and 1 <= month <= 12


def mykad_ok(digits: str) -> bool:
    month = int(digits[2:4])
    day = int(digits[4:6])
    state = int(digits[6:8])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    return 1 <= state <= 16 or 21 <= state <= 82


def phone_jurisdiction(digits: str, has_plus: bool, context: bool) -> str:
    if has_plus:
        if digits.startswith("65") and len(digits) == 10 and digits[2] in "3689":
            return "sg-pdpa"
        if digits.startswith("66") and len(digits) == 11 and digits[2] in "689":
            return "th-pdpa"
        if digits.startswith("62") and 11 <= len(digits) <= 13 and digits[2] == "8":
            return "id-pdp"
        if digits.startswith("60") and 10 <= len(digits) <= 12 and digits[2] == "1":
            return "my-pdpa"
        if digits.startswith("63") and len(digits) == 12 and digits[2] == "9":
            return "ph-dpa"
        return ""
    if not context:
        return ""
    if len(digits) == 8 and digits[0] in "89":
        return "sg-pdpa"
    if len(digits) == 10 and digits[0] == "0" and digits[1] in "689":
        return "th-pdpa"
    if 10 <= len(digits) <= 12 and digits.startswith("08"):
        return "id-pdp"
    if len(digits) in (10, 11) and digits.startswith("01"):
        return "my-pdpa"
    if len(digits) == 11 and digits.startswith("09"):
        return "ph-dpa"
    return ""
