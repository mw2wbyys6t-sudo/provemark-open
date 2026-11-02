from __future__ import annotations

import re

SECRET_RULES: list[dict[str, object]] = [
    {
        "id": "SEC-001",
        "name": "OpenAI / 兼容端点 API Key",
        "pattern": re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{24,}"),
        "severity": "critical",
        "remediation": "立即到服务商控制台吊销该 Key，改为从环境变量读取，并清理 Git 历史（git filter-repo 或 BFG）。",
        "reference": "https://platform.openai.com/api-keys",
    },
    {
        "id": "SEC-002",
        "name": "Anthropic API Key",
        "pattern": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}"),
        "severity": "critical",
        "remediation": "吊销该 Key，改用环境变量注入；若已推送远端，必须视为已泄漏并轮换。",
        "reference": "https://docs.anthropic.com/",
    },
    {
        "id": "SEC-003",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        "severity": "critical",
        "remediation": "在 IAM 中禁用并轮换该访问密钥，改用实例角色或短期凭证。",
        "reference": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    },
    {
        "id": "SEC-004",
        "name": "AWS Secret Access Key 赋值",
        "pattern": re.compile(
            r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"
        ),
        "severity": "critical",
        "remediation": "轮换密钥，改由运行环境的凭证链提供，不要写进仓库。",
        "reference": "",
    },
    {
        "id": "SEC-005",
        "name": "GitHub Token",
        "pattern": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
        "severity": "critical",
        "remediation": "到 GitHub Settings → Developer settings 吊销该 Token，改用 Actions 的 GITHUB_TOKEN 或 OIDC。",
        "reference": "https://github.com/settings/tokens",
    },
    {
        "id": "SEC-006",
        "name": "Slack Token",
        "pattern": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
        "severity": "high",
        "remediation": "吊销应用 Token 并重新授权。",
        "reference": "",
    },
    {
        "id": "SEC-007",
        "name": "Google API Key",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "severity": "high",
        "remediation": "在 GCP 控制台限制该 Key 的 API 与来源，或吊销重建。",
        "reference": "",
    },
    {
        "id": "SEC-008",
        "name": "Stripe 线上密钥",
        "pattern": re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
        "severity": "critical",
        "remediation": "立即在 Stripe Dashboard 轮换密钥，并检查是否有异常收费。",
        "reference": "https://dashboard.stripe.com/apikeys",
    },
    {
        "id": "SEC-009",
        "name": "私钥文件内容",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "severity": "critical",
        "remediation": "吊销对应证书/密钥对，生成新密钥；私钥不得进入版本库。",
        "reference": "",
    },
    {
        "id": "SEC-010",
        "name": "Hugging Face Token",
        "pattern": re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        "severity": "high",
        "remediation": "在 Hugging Face 设置中吊销该 Token。",
        "reference": "https://huggingface.co/settings/tokens",
    },
    {
        "id": "SEC-011",
        "name": "npm Token",
        "pattern": re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
        "severity": "high",
        "remediation": "执行 npm token revoke，并改用 CI 的 OIDC 或作用域受限 Token。",
        "reference": "",
    },
    {
        "id": "SEC-012",
        "name": "PyPI Token",
        "pattern": re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}"),
        "severity": "critical",
        "remediation": "在 PyPI 账户设置中吊销该 Token，改用 Trusted Publishing。",
        "reference": "",
    },
    {
        "id": "SEC-013",
        "name": "SendGrid API Key",
        "pattern": re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\b"),
        "severity": "high",
        "remediation": "吊销该 Key 并重新签发。",
        "reference": "",
    },
    {
        "id": "SEC-014",
        "name": "Telegram Bot Token",
        "pattern": re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
        "severity": "high",
        "remediation": "通过 BotFather 撤销并重新生成 Token。",
        "reference": "",
    },
    {
        "id": "SEC-015",
        "name": "URL 内嵌账号密码",
        "pattern": re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]{2,40}:[^/\s:@]{6,}@[^\s'\"]+"),
        "severity": "high",
        "remediation": "把凭据从 URL 中移除，改用环境变量或密钥管理服务。",
        "reference": "",
    },
    {
        "id": "SEC-016",
        "name": "JWT Token",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "severity": "medium",
        "remediation": "确认该 JWT 是否为真实签发；测试令牌建议使用明显的占位值。",
        "reference": "",
    },
]

GENERIC_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|secret[_-]?key|token|access[_-]?token|auth[_-]?token|"
    r"password|passwd|pwd|client[_-]?secret|private[_-]?key|app[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key|hmac[_-]?key|master[_-]?key|session[_-]?key|"
    r"signing[_-]?secret)\b\s*[:=]\s*"
    r"['\"](?P<value>[^'\"\n]{12,})['\"]"
)

PLACEHOLDER_TOKENS = (
    "example",
    "sample",
    "dummy",
    "placeholder",
    "your-",
    "your_",
    "yourkey",
    "xxxx",
    "****",
    "changeme",
    "change-me",
    "change_me",
    "replace",
    "redacted",
    "fake",
    "test-key",
    "test_key",
    "testkey",
    "sk-test",
    "abcdefghijklmnop",
    "not-a-real",
    "todo",
    "sk-xxx",
    "abcdefg123456",
    "<",
    ">",
    "${",
    "{{",
    "%s",
    "os.environ",
    "getenv",
    "process.env",
    "dotenv",
)


def looks_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in PLACEHOLDER_TOKENS)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    import math

    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def mask(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) <= 8:
        return cleaned[:2] + "****"
    return f"{cleaned[:4]}****{cleaned[-4:]}"
