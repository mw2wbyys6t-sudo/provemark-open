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
CARD_PATTERN = re.compile(r"(?<![\d])((?:\d[ -]?){12,18}\d)(?![\d])")
# 卡号只靠 Luhn 判定会误伤：13–19 位数字在现实里更常见的身份是订单号、
# 业务 ID、URL 里的主键、commit SHA。先按数字形态匹配，再看它出现在什么语境。
URL_SPAN = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s\"'<>)\]]+")
MARKDOWN_TARGET = re.compile(r"\]\(([^()\s]*)\)")
FILE_SUFFIX = re.compile(r"\.[A-Za-z0-9]{1,6}(?![A-Za-z0-9])")
CARD_HINT = re.compile(
    r"(?i)(\bcard\w*\b|卡号|信用卡|银行卡|银联|\bpassword\b|\bpan\b|\bexpiry\b|\bexpire\b|"
    r"\bvisa\b|\bmastercard\b|\bamex\b|\bunionpay\b|\bdiscover\b|\bjcb\b|\bmaestro\b|"
    r"\bdebit\b|\bcredit\b|\bcvv\b|\bcvc\b)"
)
WORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
PATH_CHARS = WORD_CHARS | frozenset("./\\:")
HEX_CHARS = frozenset("0123456789abcdefABCDEF")
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


def _token_bounds(line: str, start: int, end: int, allowed) -> tuple[int, int]:
    left = start
    while left > 0 and line[left - 1] in allowed:
        left -= 1
    right = end
    while right < len(line) and line[right] in allowed:
        right += 1
    return left, right


def _span_contains(line: str, start: int, end: int, pattern: re.Pattern[str], group: int = 0) -> bool:
    for match in pattern.finditer(line):
        begin, finish = match.span(group)
        if begin <= start and end <= finish:
            return True
    return False


def card_context_ok(line: str, match: re.Match[str]) -> bool:
    """这个数字所在的位置，支持「它是一张银行卡号」的判断吗？

    Luhn 只能证明数字「像卡号」：URL 里的业务主键、文件路径、commit SHA、
    19 位雪花 ID 都能通过校验。没有卡号语境的数字一律放过。
    """
    start, end = match.span(1)
    digits = re.sub(r"\D", "", match.group(1))
    if _span_contains(line, start, end, URL_SPAN):
        return False
    if _span_contains(line, start, end, MARKDOWN_TARGET, 1):
        return False
    path_left, path_right = _token_bounds(line, start, end, PATH_CHARS)
    path_token = line[path_left:path_right]
    if "/" in path_token or "\\" in path_token:
        return False
    if FILE_SUFFIX.match(line[end:]):
        return False
    word_left, word_right = _token_bounds(line, start, end, WORD_CHARS)
    word_token = line[word_left:word_right]
    if len(word_token) >= 7 and set(word_token) <= HEX_CHARS and set(word_token) - set("0123456789"):
        return False
    hint = bool(CARD_HINT.search(line))
    before = line[start - 1] if start > 0 else ""
    after = line[end] if end < len(line) else ""
    if not hint and (before.isalpha() or after.isalpha()):
        return False
    if len(digits) == 19 and not hint:
        return False
    return True


class _CardMatcher:
    """银行卡号匹配器：命中数字后再按语境判断它是不是卡号。"""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self._pattern = pattern

    def finditer(self, line: str):
        for match in self._pattern.finditer(line):
            if card_context_ok(line, match):
                yield match


CARD = _CardMatcher(CARD_PATTERN)


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
