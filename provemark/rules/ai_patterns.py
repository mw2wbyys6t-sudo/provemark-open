from __future__ import annotations

import re

AI_PATTERNS: list[dict[str, object]] = [
    {
        "id": "AI-001",
        "title": "占位密钥 / 占位配置残留",
        "severity": "medium",
        "languages": ("py", "js", "ts", "go", "rs", "generic"),
        "pattern": re.compile(
            r"(?i)(?:\byour[_-]?(?:api[_-]?)?key\b|\bsk-xxx+\b|\breplace[_-]?me\b|\bchangeme\b|"
            r"<your[^>\n]{0,30}>|\binsert[_-]?key[_-]here\b|\btodo:?\s*add\s+(?:key|token)\b)"
        ),
        "message": "代码里留着占位凭据，短期能跑，长期会变成“以为配好了”的故障源。",
        "remediation": "改为从环境变量读取并在缺失时快速失败（fail fast），同时补一份 .env.example 说明需要哪些变量。",
    },
    {
        "id": "AI-002",
        "title": "未完成实现标记",
        "severity": "info",
        "languages": ("py", "js", "ts", "go", "rs", "generic"),
        "pattern": re.compile(r"(?i)\b(TODO|FIXME|XXX|HACK)\b"),
        "message": "存在未完成标记。AI 生成代码常见“先搭骨架、细节留 TODO”，合入前需要确认是否真的可交付。",
        "remediation": "要么补完实现，要么创建 issue 并把标记替换为带 issue 链接的说明。",
    },
    {
        "id": "AI-003",
        "title": "抽象方法未实现",
        "severity": "info",
        "languages": ("py", "ts", "rs"),
        "pattern": re.compile(r"(?:raise\s+NotImplementedError|throw\s+new\s+Error\(\s*['\"]Not implemented)"),
        "message": "存在未实现的调用路径，运行时会直接抛错。基类用 `raise NotImplementedError` 声明子类义务是正常写法；只有具体类里被真实请求命中的分支才是问题。",
        "remediation": "确认这是基类契约还是真的漏实现：抽象/协议方法可以保留（更推荐 @abstractmethod）；具体类里的分支要么补实现，要么删掉。",
    },
    {
        "id": "AI-004",
        "title": "异常被静默吞掉",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "pattern": re.compile(
            r"(?:except\s*(?:Exception|BaseException|[A-Za-z_.]+)?(?:\s+as\s+\w+)?\s*:\s*(?:pass|\.\.\.)\s*(?:#.*)?$)"
            r"|(?:catch\s*(?:\([^)]*\))?\s*\{\s*\})"
        ),
        "message": "异常被吞掉，出错时没有任何信号，排查成本极高。",
        "remediation": "至少记录日志并保留上下文；确实要忽略时，写明为什么可以忽略。",
    },
    {
        "id": "AI-005",
        "title": "危险调用（RCE / 反序列化 / 关闭校验）",
        "severity": "high",
        "languages": ("py",),
        "pattern": re.compile(
            r"(?:(?<![\w.'\"`])eval\s*\(|(?<![\w.'\"`])exec\s*\(|pickle\.loads?\s*\(|"
            r"yaml\.load\s*\((?![^)\n]*Loader)|subprocess\.[a-z_]+\([^)\n]*shell\s*=\s*True|"
            r"(?<![\w.'\"`])os\.system\s*\(|os\.popen\s*\(|verify\s*=\s*False)"
        ),
        "message": "该调用可被外部输入利用，或关闭了安全校验。",
        "remediation": "用明确的解析器替代 eval/exec；反序列化改用 json；子进程使用参数列表且不拼 shell；证书校验不要关闭。",
    },
    {
        "id": "AI-006",
        "title": "前端危险注入点",
        "severity": "high",
        "languages": ("js", "ts"),
        "pattern": re.compile(
            r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(|new\s+Function\s*\(|"
            r"child_process\.exec\s*\()"
        ),
        "message": "直接拼接 HTML 或执行字符串代码，容易形成 XSS / 命令注入。",
        "remediation": "改用文本节点或经过消毒的渲染方式；命令行调用使用 execFile 并传参数数组。",
    },
    {
        "id": "AI-007",
        "title": "生产代码中的示例 / mock 数据",
        "severity": "low",
        "languages": ("py", "js", "ts", "go", "rs", "generic"),
        "pattern": re.compile(
            r"(?i)(?:lorem\s+ipsum|foo@example\.(?:com|org)|@example\.(?:com|org)|"
            r"dummy[_-]?(?:data|user|token)|mock[_-]?(?:data|user)|fake[_-]?(?:data|user))"
        ),
        "message": "看起来是示例数据或 mock 数据，出现在非测试路径会被误当成真实逻辑。",
        "remediation": "把示例数据移入 tests/fixtures，或替换为真实数据来源。",
    },
    {
        "id": "AI-008",
        "title": "调试输出残留",
        "severity": "low",
        "languages": ("py", "js", "ts"),
        "pattern": re.compile(r"(?:console\.(?:log|debug)\s*\(|debugger\s*;?|fmt\.Println\s*\()"),
        "message": "调试输出可能泄漏内部信息，也会污染用户看到的日志。",
        "remediation": "改用项目统一的日志组件，或删除调试语句。",
    },
    {
        "id": "AI-009",
        "title": "硬编码的个人机器路径",
        "severity": "low",
        "languages": ("py", "js", "ts", "go", "rs", "generic"),
        "pattern": re.compile(r"(?:/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._-]+\\\\)"),
        "message": "硬编码的绝对路径在别人机器上一定失效。",
        "remediation": "改为基于项目根目录或用户目录的相对路径（pathlib / os.path.expanduser）。",
    },
    {
        "id": "AI-010",
        "title": "关闭类型检查 / 全文件忽略",
        "severity": "medium",
        "languages": ("ts",),
        "pattern": re.compile(r"(?:@ts-nocheck|@ts-ignore)"),
        "message": "整文件或整行关闭类型检查，会把 AI 生成的类型错误掩盖到运行时。",
        "remediation": "修复类型错误；确需忽略时限定到具体一行并附原因。",
    },
    {
        "id": "AI-011",
        "title": "空实现函数体",
        "severity": "low",
        "languages": ("py",),
        "pattern": re.compile(r"^(?:\s*)def\s+\w+\([^)]*\)\s*(?:->[^:]+)?:\s*(?:pass|\.\.\.)\s*$"),
        "message": "函数体为空，可能是 AI 生成的脚手架残留。",
        "remediation": "补实现或删除占位函数。",
    },
    {
        "id": "AI-015",
        "title": "外部请求没有超时设置",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "pattern": re.compile(
            r"""(?ix)
            (?:
                \bfetch\s*\((?![^)]*\bsignal\b)
              | \baxios\.(?:get|post|put|patch|delete)\s*\((?![^)]*\btimeout\b)
              | \b(?:requests|httpx)\.(?:get|post|put|patch|delete)\s*\((?![^)]*\btimeout\b)
            )
            """
        ),
        "message": "外部调用没有超时：对端变慢或挂起时，当前请求会一直占着连接/线程，最终把整个服务拖垮（雪崩）。",
        "remediation": "Python 用 `requests.get(url, timeout=(3.05, 10))`；JS 用 `AbortSignal.timeout(10_000)` 或 axios 的 `timeout`；同时给重试加退避与上限。",
    },
    {
        "id": "AI-018",
        "title": "ORM 开了 schema 自动同步/强制重建",
        "severity": "high",
        "languages": ("js", "ts"),
        "pattern": re.compile(r"(?:synchronize\s*:\s*true|dropSchema\s*:\s*true|\.sync\s*\(\s*\{\s*force\s*:\s*true)"),
        "message": "`synchronize/dropSchema/force` 会在启动或测试时按实体模型改库（甚至删表重建）。生产上这意味着数据丢失，且改动不可审计。",
        "remediation": "生产一律用迁移（migration）管理 schema；`synchronize` 只在本地开发打开，测试库用一次性容器。",
    },
    {
        "id": "AI-019",
        "title": "Django 默认开放主机/CORS/CSRF",
        "severity": "medium",
        "languages": ("py",),
        "pattern": re.compile(
            r"(?:ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|"
            r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CSRF_TRUSTED_ORIGINS\s*=\s*\[\s*['\"]\*)"
        ),
        "message": "把允许主机/CORS 放开到 `*`，等于允许任意站点在浏览器里带着用户凭据调用你的接口（也绕过 Host 头校验）。",
        "remediation": "写成明确的域名列表（`example.com`、`api.example.com`），按环境从配置读取；CORS 只放行确实需要的来源。",
    },
    {
        "id": "AI-020",
        "title": "用 print / console.log 当日志",
        "severity": "low",
        "languages": ("py", "js", "ts"),
        "pattern": re.compile(r"^\s*(?:print\s*\(|console\.log\s*\()"),
        "message": "散落的 print/console.log 没有级别、没有时间戳、无法采样或关闭；线上排障时它们既吵又不够用。",
        "remediation": "改用结构化日志（Python `logging`、JS `pino`/`winston`），带 request id、级别与关键字段；CLI 输出才用 print。",
    },
    {
        "id": "AI-025",
        "title": "用 list 当队列（pop(0)/insert(0)）",
        "severity": "low",
        "languages": ("py",),
        "pattern": re.compile(r"(?:\.pop\s*\(\s*0\s*\)|\.insert\s*\(\s*0\s*,)"),
        "message": "`list.pop(0)` / `list.insert(0, x)` 每次都要搬移整个列表，是 O(n)；在循环里用就是 O(n²)。",
        "remediation": "需要队列用 `collections.deque`（`popleft`/`appendleft`），或维护一个读指针；需要有序插入用 `bisect.insort`。",
    },
    {
        "id": "AI-026",
        "title": "用 iterrows 逐行遍历 DataFrame",
        "severity": "low",
        "languages": ("py",),
        "pattern": re.compile(r"\.iterrows\s*\(\s*\)"),
        "message": "`iterrows` 逐行装箱，比向量化慢一到两个数量级；大表上会把批处理拖成小时级。",
        "remediation": "优先向量化（列运算、`map`/`apply`）；必须逐行时用 `itertuples` 或转成 numpy 数组。",
    },
]

# 跨行判定（循环体里串行 await / N+1 查询），由 scanners.ai_code 的 _loop_findings 使用。
ENGINEERING_LOOP_RULES: list[dict[str, object]] = [
    {
        "id": "AI-016",
        "title": "循环里串行 await（可并发/批量）",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "signal": "await",
        "message": "在循环里逐个 await 网络/数据库调用，延迟会线性累加（10 次 50ms 就是 500ms），吞吐被串行化。",
        "remediation": "能并发的用 `asyncio.gather` / `Promise.all`（注意并发上限与错误处理）；能批量的合并成一次查询；确实要顺序执行时在注释里写明原因。",
    },
    {
        "id": "AI-017",
        "title": "循环里发查询（N+1）",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "signal": "query",
        "message": "在循环里逐条查数据库是典型的 N+1：数据量一上来，请求数 = 列表长度 + 1，数据库和连接池都会被拖垮。",
        "remediation": "一次批量取（`WHERE id IN (...)` / `include`/`selectinload`/`populate`），或让查询层返回聚合结果；ORM 关系用预加载。",
    },
    {
        "id": "AI-021",
        "title": "循环里逐条请求外部接口（批量更好）",
        "severity": "medium",
        "languages": ("py", "js", "ts"),
        "signal": "io",
        "message": "同步 HTTP 调用放进循环：N 次往返串行执行，延迟线性累加，还会放大对端限流/超时。",
        "remediation": "优先用批量接口或一次查询；必须逐条时改用异步并发（有限并发）并加超时/退避。",
    },
    {
        "id": "AI-022",
        "title": "循环里用 += 拼接字符串（O(n²)）",
        "severity": "low",
        "languages": ("py", "js", "ts"),
        "signal": "concat",
        "message": "字符串在循环里 `+=`，每次都可能重新分配并复制整段内容，累计是 O(n²)；数据一多就慢得离谱。",
        "remediation": "先收集到列表，最后 `''.join(parts)`（JS 用数组 `join`）；大批量输出用流式写入。",
    },
    {
        "id": "AI-024",
        "title": "循环里 concat DataFrame（越拼越慢）",
        "severity": "medium",
        "languages": ("py",),
        "signal": "frame",
        "message": "在循环里 `pd.concat` 会反复复制整张表，整体是 O(n²)；数据量大时内存和耗时都会爆。",
        "remediation": "先 append 到列表，循环外一次性 `pd.concat(list)`；更彻底的是向量化或分块读取。",
    },
]

IMPORT_PATTERNS = {
    "py": [
        re.compile(r"^\s*import\s+([A-Za-z_][\w.]*)"),
        re.compile(r"^\s*from\s+([A-Za-z_][\w.]*)\s+import\b"),
    ],
    "js": [
        re.compile(r"""^\s*import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]"""),
        re.compile(r"""^\s*export\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]"""),
        re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
        re.compile(r"""^\s*import\s+['"]([^'"]+)['"]"""),
    ],
    "ts": [
        re.compile(r"""^\s*import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]"""),
        re.compile(r"""^\s*export\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]"""),
        re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    ],
    "go": [
        re.compile(r'^\s*(?:import\s+)?(?:[A-Za-z_.]+\s+)?"([a-zA-Z0-9_.\-/]+)"\s*$'),
        re.compile(r'^\s*import\s+"([a-zA-Z0-9_.\-/]+)"'),
    ],
}

JS_BUILTIN_PREFIXES = (
    "node:",
    "fs",
    "path",
    "os",
    "url",
    "http",
    "https",
    "crypto",
    "stream",
    "util",
    "events",
    "child_process",
    "buffer",
    "zlib",
    "assert",
    "net",
    "tls",
    "dns",
    "readline",
    "worker_threads",
    "process",
    "timers",
    "querystring",
    "string_decoder",
    "perf_hooks",
    "async_hooks",
    "v8",
    "vm",
    "cluster",
    "dgram",
    "module",
    "repl",
    "tty",
    "inspector",
)

GO_STDLIB_HINTS = (
    "fmt",
    "os",
    "io",
    "net",
    "time",
    "strings",
    "strconv",
    "errors",
    "bytes",
    "bufio",
    "context",
    "encoding",
    "crypto",
    "math",
    "sort",
    "sync",
    "path",
    "reflect",
    "regexp",
    "runtime",
    "testing",
    "unicode",
    "hash",
    "log",
    "mime",
    "flag",
    "database",
    "compress",
    "container",
    "archive",
    "embed",
    "html",
    "image",
    "index",
    "debug",
    "go",
    "syscall",
    "text",
)

SERVICE_DIRS = ("/api/", "/routes/", "/server/", "/services/", "/core/", "/controllers/")

PY_FAKE_MODULES = {
    "requests",
    "numpy",
    "pandas",
    "torch",
    "cv2",
    "PIL",
    "flask",
    "fastapi",
    "django",
    "aiohttp",
    "yaml",
    "dotenv",
    "pydantic",
    "sqlalchemy",
    "httpx",
    "openai",
    "anthropic",
    "sklearn",
    "transformers",
    "onnxruntime",
    "mediapipe",
    "psd_tools",
    "rembg",
}
