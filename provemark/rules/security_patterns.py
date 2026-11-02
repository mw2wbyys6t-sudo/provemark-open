"""应用层安全规则：CWE / OWASP 映射的高信号代码模式。

设计原则（为什么不是“全部安全检查”）：

- **只报代码里能看见的确定模式**：字符串拼接进 SQL、`verify=False`、`md5` 口令哈希……
  这些是 OWASP Top 10 里最常见的几类，也是 AI 生成代码最容易写出来的几类；
- **每条规则带 CWE 与 OWASP 映射**，报告里能直接说清“这属于哪类问题、对应哪个标准条目”；
- **宁可少报不误报**：注释/文档字符串由 `codemask` 屏蔽；测试与脚本降级；
- **语言精确**：同一类问题在 py / js / go 里写法不同，不共用模糊正则。
"""
from __future__ import annotations

import re

# 语言集合：与 scanners.security 的 LANG_BY_SUFFIX 对应
PY = ("py",)
JS = ("js", "ts")
GO = ("go",)
C = ("c", "cpp")

SECURITY_PATTERNS: list[dict[str, object]] = [
    {
        "id": "VUL-001",
        "title": "SQL 注入：查询语句由字符串拼接/格式化产生",
        "severity": "high",
        "languages": ("py", "js", "ts", "go"),
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "confidence": 0.85,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                (?:execute|executemany|raw|extra)\s*\(\s*(?:f|rf|fr)["'][^"']*\b(?:select|insert|update|delete|where)\b
              | (?:execute|executemany|raw)\s*\(\s*["'][^"']*\b(?:select|insert|update|delete)\b[^"']*["']\s*(?:%|\+|\.format\s*\()
              | (?:query|execute)\s*\(\s*[`"'][^`"']*\b(?:select|insert|update|delete)\b[^`"']*\$\{
              | (?:Query|Exec|QueryRow)\s*\(\s*"[^"]*\b(?:select|insert|update|delete)\b[^"]*"\s*\+
              | fmt\.Sprintf\s*\(\s*"[^"]*\b(?:select|insert|update|delete)\b[^"]*%[sv]
            )
            """,
        ),
        "message": "SQL 由拼接或格式化生成，用户输入可以改变查询结构——这是最经典的注入面。",
        "remediation": "改用参数化查询（占位符 + 参数列表）；ORM 用绑定参数，绝不把用户输入拼进 SQL 文本。",
    },
    {
        "id": "VUL-002",
        "title": "命令注入：命令字符串由用户输入拼接后交给 shell",
        "severity": "high",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-78",
        "owasp": "A03:2021 Injection",
        "confidence": 0.85,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                os\.(?:system|popen)\s*\(\s*(?:f|rf|fr)["']
              | os\.(?:system|popen)\s*\(\s*["'][^"']*["']\s*(?:%|\+|\.format\s*\()
              | subprocess\.[a-z_]+\((?=[^)]*(?:f["']|\+\s*\w|%\s*\(|\.format\s*\())[^)]*shell\s*=\s*True
              | child_process\.(?:exec|execSync)\s*\(\s*[`"'][^`"']*\$\{
              | child_process\.(?:exec|execSync)\s*\(\s*[^)]*\+\s*(?:req\.|params\.|args)
            )
            """,
        ),
        "message": "把拼接出来的字符串交给 shell，等于把参数解析权交给了输入方（空格、`;`、`$()` 都能改变命令）。",
        "remediation": "用参数列表调用（`subprocess.run([...])` / `execFile`），不经过 shell；必须拼接时对每个参数做白名单校验。",
    },
    {
        "id": "VUL-003",
        "title": "服务端模板注入：模板内容来自用户输入",
        "severity": "high",
        "languages": ("py",),
        "cwe": "CWE-1336",
        "owasp": "A03:2021 Injection",
        "confidence": 0.8,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                render_template_string\s*\([^)]*(?:request\.|args\b|form\b|json\b|user_input|user\w*\.)
              | Template\s*\([^)]*(?:request\.|args\b|form\b|user_input)[^)]*\)\s*\.render
            )
            """,
        ),
        "message": "模板文本由用户提供时，`{{ ... }}` 里的表达式会在服务端执行（SSTI）。",
        "remediation": "模板必须来自代码/文件；用户输入只作为模板变量传入，不要拼进模板源码。",
    },
    {
        "id": "VUL-004",
        "title": "不可信数据反序列化",
        "severity": "high",
        "languages": ("py",),
        "cwe": "CWE-502",
        "owasp": "A08:2021 Software and Data Integrity Failures",
        "confidence": 0.85,
        "pattern": re.compile(r"(?:marshal\.loads|dill\.loads|jsonpickle\.decode|shelve\.open)\s*\("),
        "message": "这些反序列化器可以构造任意对象/执行代码路径，处理外部数据时等于给出代码执行面。",
        "remediation": "外部数据只用 JSON / MessagePack 等纯数据格式；必须兼容旧格式时加签名校验（HMAC）并限制来源。",
    },
    {
        "id": "VUL-005",
        "title": "未转义的 HTML 输出（XSS）",
        "severity": "high",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "confidence": 0.8,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                Markup\s*\(\s*(?:f["']|[^)]*(?:request\.|args\b|form\b|user_input))
              | document\.write(?:ln)?\s*\(\s*[`"'][^`"']*(?:\$\{|\+\s*\w)
            )
            """,
        ),
        "message": "把不可信内容标记为安全 HTML 或直接写进文档，浏览器会当代码执行。",
        "remediation": "默认转义输出；确需富文本时用白名单清洗（bleach/DOMPurify），不要用 `Markup`/`|safe` 直接放行。",
    },
    {
        "id": "VUL-006",
        "title": "路径穿越：文件名/路径来自用户输入",
        "severity": "high",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-22",
        "owasp": "A01:2021 Broken Access Control",
        "confidence": 0.8,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                (?:open|send_file|send_from_directory|Path)\s*\([^)]*(?:request\.(?:args|form|values|json|files)|req\.(?:query|params|body)|user_input)
              | (?:fs\.(?:readFile|createReadStream|writeFile|unlink)|res\.sendFile)\s*\([^)]*(?:req\.(?:query|params|body)|user_input)
            )
            """,
        ),
        "message": "用户能控制路径时，`../` 可以跳出预期目录读取或覆盖任意文件。",
        "remediation": "用固定根目录 + `Path.resolve()` 后校验仍在根内；文件名只允许白名单字符，客户端传来的名字只作展示。",
    },
    {
        "id": "VUL-007",
        "title": "SSRF：请求目标来自用户输入",
        "severity": "medium",
        "languages": ("py", "js", "ts", "go"),
        "cwe": "CWE-918",
        "owasp": "A10:2021 Server-Side Request Forgery",
        "confidence": 0.75,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                (?:requests|httpx)\.(?:get|post|put|request)\s*\([^)]*(?:request\.|req\.|user_input|url_from)
              | urllib\.request\.urlopen\s*\([^)]*(?:request\.|req\.|user_input)
              | fetch\s*\(\s*(?:req\.|params\.|user_input)
              | http\.(?:Get|Post|Head)\s*\(\s*r\.URL\.Query
            )
            """,
        ),
        "message": "服务端按用户给的地址发请求，可以被用来扫内网、读元数据服务（169.254.169.254）或打内部 API。",
        "remediation": "目标域名/IP 用白名单；解析后拒绝私网/回环/链路本地地址；禁止跟随重定向到内网。",
    },
    {
        "id": "VUL-008",
        "title": "弱哈希（MD5/SHA1）",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-327",
        "owasp": "A02:2021 Cryptographic Failures",
        "confidence": 0.7,
        "escalate_on": re.compile(r"(?i)(?:password|passwd|pwd|credential|token|secret|api[_-]?key)"),
        "escalated_severity": "high",
        "pattern": re.compile(
            r"""(?ix)
            ^(?=.*\b(?:password|passwd|pwd|token|secret|credential|auth|session|sign|hmac|cert|api[_-]?key)\b)
            .*
            (?:
                hashlib\.(?:md5|sha1)\s*\(
              | crypto\.createHash\(\s*['"](?:md5|sha1)['"]
              | createHash\(\s*['"](?:md5|sha1)['"]
            )
            """,
        ),
        "message": "MD5/SHA1 已被证明可构造碰撞，不能用于口令、令牌或签名；用于文件校验和时需确认不涉及安全判定。",
        "remediation": "口令用 bcrypt/argon2/scrypt；完整性校验用 SHA-256 或 BLAKE2。",
    },
    {
        "id": "VUL-009",
        "title": "用非密码学随机数生成令牌/密钥",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-338",
        "owasp": "A02:2021 Cryptographic Failures",
        "confidence": 0.8,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                (?:token|secret|nonce|salt|password|session|api[_-]?key)\w*\s*=\s*random\.(?:random|randint|choice|choices|sample)\s*\(
              | (?:token|secret|nonce|salt|session)\w*\s*=\s*Math\.random\s*\(
            )
            """,
        ),
        "message": "`random` 是可预测的 PRNG，输出可以被推断；用在令牌、盐、会话 ID 上等于弱化认证。",
        "remediation": "Python 用 `secrets.token_urlsafe()`；Node 用 `crypto.randomBytes()` / `crypto.randomUUID()`。",
    },
    {
        "id": "VUL-010",
        "title": "关闭 TLS 证书校验",
        "severity": "high",
        "languages": ("py", "js", "ts", "go"),
        "cwe": "CWE-295",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "confidence": 0.9,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                ssl\._create_unverified_context
              | ssl\.CERT_NONE
              | check_hostname\s*=\s*False
              | rejectUnauthorized\s*:\s*false
              | NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0
              | InsecureSkipVerify\s*:\s*true
            )
            """,
        ),
        "message": "关闭证书校验后，任何中间人都能冒充对端，加密通道失去认证意义。",
        "remediation": "保持校验开启；自签证书把 CA 加入信任库，而不是关闭校验。",
        "test_severity": "low",
    },
    {
        "id": "VUL-011",
        "title": "弱加密算法或模式（ECB / DES / createCipher）",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-327",
        "owasp": "A02:2021 Cryptographic Failures",
        "confidence": 0.75,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                AES\.MODE_ECB
              | \bDES\.new\s*\(
              | crypto\.createCipher\s*\(
              | algorithm\s*:\s*['"](?:des|des-ede|rc4)
            )
            """,
        ),
        "message": "ECB 相同明文块产生相同密文，DES/RC4 强度不足，`createCipher` 没有随机 IV。",
        "remediation": "用 AES-256-GCM 或 ChaCha20-Poly1305（有认证的 AEAD），每次随机 IV；不要用 ECB/DES/RC4。",
    },
    {
        "id": "VUL-012",
        "title": "JWT 校验被关闭或接受 alg=none",
        "severity": "high",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-347",
        "owasp": "A07:2021 Identification and Authentication Failures",
        "confidence": 0.85,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                jwt\.decode\([^)]*(?:verify\s*=\s*False|verify_signature[^)]*False|algorithms\s*=\s*\[\s*\])
              | jwt\.verify\([^)]*(?:ignoreExpiration\s*:\s*true|algorithms\s*:\s*\[\s*['"]none)
              | ['"]alg['"]\s*:\s*['"]none['"]
            )
            """,
        ),
        "message": "不校验签名（或接受 `alg=none`）时，任何人都能伪造令牌并冒充任意用户。",
        "remediation": "固定允许的算法（如 RS256）并校验签名、issuer、audience、exp；绝不信任头部里的 `alg`。",
    },
    {
        "id": "VUL-013",
        "title": "Cookie 缺少安全属性",
        "severity": "low",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-614",
        "owasp": "A05:2021 Security Misconfiguration",
        "confidence": 0.75,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                set_cookie\([^)]*(?:secure\s*=\s*False|httponly\s*=\s*False)
              | (?:httpOnly|secure)\s*:\s*false
            )
            """,
        ),
        "message": "会话 Cookie 关闭 `Secure`/`HttpOnly` 后，可以被明文传输或被脚本读取。",
        "remediation": "会话 Cookie 一律 `Secure; HttpOnly; SameSite=Lax/Strict`。",
    },
    {
        "id": "VUL-014",
        "title": "生产代码开启调试模式",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "cwe": "CWE-489",
        "owasp": "A05:2021 Security Misconfiguration",
        "confidence": 0.8,
        "pattern": re.compile(
            r"""(?ix)
            (?:
                app\.run\([^)]*debug\s*=\s*True
              | ^\s*DEBUG\s*=\s*True\s*$
              | app\.set\(\s*['"]env['"]\s*,\s*['"]development['"]
            )
            """,
        ),
        "message": "调试模式会暴露堆栈、交互式调试器（Werkzeug console）与内部配置，等于把 RCE 入口留在线上。",
        "remediation": "调试开关由环境变量控制，生产默认关闭；用独立配置区分 dev/prod。",
        "test_severity": "low",
    },
    {
        "id": "VUL-015",
        "title": "XML 解析允许外部实体（XXE）",
        "severity": "high",
        "languages": ("py",),
        "cwe": "CWE-611",
        "owasp": "A05:2021 Security Misconfiguration",
        "confidence": 0.8,
        "pattern": re.compile(r"(?:resolve_entities\s*=\s*True|etree\.XMLParser\([^)]*resolve_entities)"),
        "message": "允许外部实体后，XML 可以读本地文件、发起内网请求（XXE）。",
        "remediation": "用 `defusedxml`，或显式 `resolve_entities=False, no_network=True`；不要解析不可信 XML。",
    },
    {
        "id": "VUL-016",
        "title": "C/C++ 危险字符串函数（缓冲区溢出）",
        "severity": "high",
        "languages": ("c", "cpp"),
        "cwe": "CWE-120",
        "owasp": "A03:2021 Injection",
        "confidence": 0.7,
        "pattern": re.compile(r"\b(?:strcpy|strcat|sprintf|gets|scanf)\s*\("),
        "message": "这些函数不做边界检查，输入长度可控时直接造成缓冲区溢出。",
        "remediation": "改用 `strncpy_s`/`snprintf`/`fgets` 并检查返回值；启用编译器加固（-D_FORTIFY_SOURCE、-fstack-protector）。",
    },
    {
        "id": "VUL-018",
        "title": "容器提权 / 挂载 Docker socket",
        "severity": "medium",
        "languages": ("generic",),
        "cwe": "CWE-250",
        "owasp": "A05:2021 Security Misconfiguration",
        "confidence": 0.85,
        "pattern": re.compile(r"(?:privileged\s*:\s*true|/var/run/docker\.sock|\b--privileged\b)"),
        "message": "特权容器或挂载 Docker socket 等于把宿主机控制权交给容器内进程。",
        "remediation": "去掉 `privileged`，按需 `cap_add` 最小能力；不要挂载 docker.sock，改用受控的构建/运维通道。",
    },
]

# GitHub Actions 脚本注入单独处理（需要看 run: 块，不是单行正则）
ACTIONS_INJECTION = {
    "id": "VUL-017",
    "title": "GitHub Actions 脚本注入：不可信事件字段进入 run",
    "severity": "high",
    "cwe": "CWE-94",
    "owasp": "A03:2021 Injection",
    "confidence": 0.8,
    "pattern": re.compile(
        r"""(?ix)\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|discussion|head_commit)\.(?:title|body)
        | head_ref)\b""",
    ),
    "message": "PR/issue 的标题或分支名是外部可控字符串，直接插进 `run:` 会被当成 shell 执行（pwn request 的常见变体）。",
    "remediation": "把事件字段经 `env:` 传入并用引号包裹（`\"$TITLE\"`），或改用 `github-script` 的上下文 API，不要直接插值进 run。",
}

# 这些文件本身就是规则定义/正则，扫描它们只会自命中
SELF_PATTERN_FILES = {
    "ai_patterns.py",
    "security_patterns.py",
    "secrets.py",
    "pii.py",
    "license_texts.py",
}
