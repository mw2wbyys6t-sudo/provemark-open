from __future__ import annotations

from ..models import CATEGORIES
from . import ai_patterns, secrets, security_patterns

MANUAL: dict[str, dict[str, str]] = {
    "SEC-017": {
        "title": "疑似硬编码密钥（高熵字符串）",
        "severity": "medium",
        "message": "被赋值的字符串熵很高，形态接近真实密钥而非配置项。",
        "remediation": "改为环境变量注入；测试数据请使用明显的占位值。",
    },
    "AI-012": {
        "title": "导入了清单中未声明的依赖",
        "severity": "high",
        "message": "代码 import 了依赖清单里没有的包。AI 生成代码时容易“顺手 import 一个看似存在的包”。",
        "remediation": "确认包真实存在并写入清单，或删除该导入。",
    },
    "AI-013": {
        "title": "检测到 AI 助手配置但没有使用声明",
        "severity": "info",
        "message": "仓库里有 AI 助手痕迹，但没有 AI_USAGE.md，无法说明哪些代码由 AI 参与。",
        "remediation": "运行 `provemark ai-usage` 生成声明骨架。",
    },
    "AI-014": {
        "title": "AI 使用声明不完整",
        "severity": "info",
        "message": "AI_USAGE.md 缺少必需小节，或仍保留「待填写」占位。",
        "remediation": "补齐工具、范围、人工复核三节。",
    },
    "PII-001": {
        "title": "仓库中出现邮箱地址",
        "severity": "low",
        "message": "源码或数据文件中出现邮箱地址。示例值无害，真实用户的邮箱属于个人信息。",
        "remediation": "测试数据改用 example.com 等保留域名；真实数据不要入库。",
        "category": "pii",
    },
    "PII-002": {
        "title": "仓库中出现手机号",
        "severity": "medium",
        "message": "按辖区移动号段匹配到疑似真实手机号。手机号是可识别到自然人的个人信息。",
        "remediation": "改用脱敏样例（如 +65****1234），真实号码移出仓库。",
        "category": "pii",
    },
    "PII-003": {
        "title": "仓库中出现政府证件号",
        "severity": "high",
        "message": "匹配到 NRIC / 泰国身份证 / NIK / MyKad / PhilSys 等证件号，属于敏感个人信息。",
        "remediation": "立即从仓库与历史中移除，改用掩码样例；如确属生产数据，按泄露流程评估通知义务。",
        "category": "pii",
    },
    "PII-004": {
        "title": "仓库中出现银行卡号",
        "severity": "high",
        "message": "通过 Luhn 校验的卡号出现在仓库里，属于支付卡数据。",
        "remediation": "立即移除并轮换相关支付凭证；测试改用官方测试卡号。",
        "category": "pii",
    },
    "PII-005": {
        "title": "疑似真实用户数据快照",
        "severity": "high",
        "message": "单个文件里出现大量不同邮箱，形态更像数据库导出或埋点快照，而不是样例数据。",
        "remediation": "确认文件来源；生产数据快照不应提交到仓库，改用合成数据。",
        "category": "pii",
    },
    "PII-006": {
        "title": "日志中输出个人信息",
        "severity": "high",
        "message": "日志语句直接拼接个人信息，会把这些数据扩散到日志平台并拉长保留周期。",
        "remediation": "打印前脱敏（邮箱/手机号/证件号），或只打印内部 ID。",
        "category": "pii",
    },
    "DEP-001": {
        "title": "依赖存在已知漏洞",
        "severity": "high",
        "message": "该依赖版本命中 OSV 安全公告，公告里通常给出了修复版本。",
        "remediation": "按公告升级到修复版本，并提交锁文件。",
    },
    "DEP-003": {
        "title": "依赖版本无法确定",
        "severity": "info",
        "message": "只声明了版本范围且没有锁文件，无法查询该依赖是否存在已知漏洞。",
        "remediation": "生成并提交锁文件。",
    },
    "DEP-004": {
        "title": "命中公告但未能获取详情",
        "severity": "medium",
        "message": "OSV 返回了公告编号，但详情请求失败或超时。",
        "remediation": "打开 osv.dev 对应页面手动确认受影响版本。",
    },
    "LIC-002": {
        "title": "许可证声明与 LICENSE 文件不一致",
        "severity": "medium",
        "message": "清单字段与许可证文件指向不同许可证，下游无法判断以哪个为准。",
        "remediation": "统一为同一 SPDX 标识。",
    },
    "LIC-003": {
        "title": "许可证文件无法识别",
        "severity": "medium",
        "message": "LICENSE 内容不匹配任何常见模板，托管平台通常也会判为未知。",
        "remediation": "替换为 SPDX 标准文本。",
    },
    "LIC-004": {
        "title": "依赖许可证与项目许可证冲突",
        "severity": "high",
        "message": "依赖使用强传染许可证（GPL/AGPL/SSPL 等），会改变你分发时的义务。",
        "remediation": "替换为宽松许可证的等价实现，或调整项目许可证并评估分发方式。",
    },
    "LIC-005": {
        "title": "依赖许可证无法确定",
        "severity": "medium",
        "message": "未能从公共数据源获取该依赖的许可证。未知许可证等于没有明确授权。",
        "remediation": "打开依赖仓库确认 LICENSE，必要时联系作者。",
    },
    "LIC-006": {
        "title": "依赖使用弱传染许可证",
        "severity": "low",
        "message": "MPL / LGPL / EPL 类许可证通常只要求公开被修改的文件本身。",
        "remediation": "保留许可证与声明；修改该依赖源码时公开对应文件。",
    },
    "LIC-007": {
        "title": "项目许可证不在团队白名单内",
        "severity": "low",
        "message": "项目自身使用的许可证不在 project.allowed_licenses 中。",
        "remediation": "确认是有意选择，或调整策略。",
    },
    "LIC-008": {
        "title": "许可证问题数量过多，已折叠",
        "severity": "info",
        "message": "依赖树较大时报告只列出最紧急的部分。",
        "remediation": "用 --format json 导出完整列表。",
    },
    "LIC-009": {
        "title": "依赖许可证与项目许可证组合冲突",
        "severity": "high",
        "message": "项目许可证与依赖许可证在组合分发时不兼容（例如 Apache-2.0 依赖进入 GPL-2.0-only 项目）。",
        "remediation": "替换为兼容许可证的依赖；或调整项目许可证；或在 license.exceptions 登记并说明分发方式。",
    },
    "LIC-010": {
        "title": "许可证组合无法自动判定",
        "severity": "info",
        "message": "组合不在已知兼容矩阵内，需人工确认分发义务。",
        "remediation": "查阅两份许可证原文，确认可否组合分发。",
    },
    "SCP-014": {
        "title": "vendored 代码缺少来源记录",
        "severity": "medium",
        "message": "拷贝进来的第三方代码没有上游地址与版本，无法回溯漏洞，也无法证明许可证来源。",
        "remediation": "运行 `provemark vendored` 生成 VENDORED.md 并补齐上游与 Commit。",
    },
    "SCP-015": {
        "title": "vendored 来源记录不完整",
        "severity": "low",
        "message": "VENDORED.md 漏了目录，或上游/版本仍标着「待补齐」。",
        "remediation": "补齐上游 URL、Commit/Tag 与修改说明。",
    },
    "HYG-014": {
        "title": "缺少 THIRD_PARTY_NOTICES",
        "severity": "low",
        "message": "仓库引用了运行时依赖，却没有第三方组件归因文件；对外分发时无法说明每个组件的许可证。",
        "remediation": "运行 `provemark notices` 生成 THIRD_PARTY_NOTICES.md。",
    },
    "HYG-015": {
        "title": "THIRD_PARTY_NOTICES 与依赖不一致",
        "severity": "info",
        "message": "归因文件没有覆盖当前依赖树里的部分组件，版本升级后容易漏掉。",
        "remediation": "重新生成：`provemark notices --force`。",
    },
    "HYG-001": {
        "title": "仓库没有许可证文件",
        "severity": "high",
        "message": "没有许可证等于保留所有权利，别人无法合法使用。",
        "remediation": "provemark fix --apply 生成 LICENSE。",
    },
    "HYG-002": {"title": "缺少 README", "severity": "medium", "message": "缺少项目说明。", "remediation": "补 README。"},
    "HYG-003": {
        "title": "缺少 SECURITY.md",
        "severity": "medium",
        "message": "没有安全披露渠道。",
        "remediation": "添加 SECURITY.md。",
    },
    "HYG-004": {
        "title": "缺少 .gitignore",
        "severity": "medium",
        "message": "没有忽略规则，密钥与产物容易被误提交。",
        "remediation": "provemark fix --apply 生成。",
    },
    "HYG-005": {
        "title": ".gitignore 没有忽略 .env",
        "severity": "high",
        "message": "一次 git add . 就可能把密钥推上去。",
        "remediation": "加入 .env 与 .env.*。",
    },
    "HYG-006": {
        "title": "环境变量文件已被提交",
        "severity": "critical",
        "message": "该文件通常含真实密钥，且已进入 Git 历史。",
        "remediation": "删除、轮换密钥、清理历史。",
    },
    "HYG-007": {
        "title": "凭据或私钥文件已被提交",
        "severity": "critical",
        "message": "私钥进入版本库即视为泄漏。",
        "remediation": "吊销凭据并清理历史。",
    },
    "HYG-008": {
        "title": "依赖 / 缓存目录被提交",
        "severity": "high",
        "message": "仓库体积膨胀且无法复现。",
        "remediation": "git rm -r --cached 并加入 .gitignore。",
    },
    "HYG-009": {
        "title": "仓库中有较大的二进制文件",
        "severity": "medium",
        "message": "大文件让克隆变慢且无法 diff。",
        "remediation": "改用 Git LFS 或对象存储。",
    },
    "HYG-010": {"title": "没有 CI 配置", "severity": "low", "message": "缺少自动化验证。", "remediation": "provemark init 生成工作流。"},
    "HYG-011": {"title": "没有找到测试文件", "severity": "info", "message": "缺少可验证行为的手段。", "remediation": "为核心路径补测试。"},
    "HYG-012": {"title": "系统垃圾文件被提交", "severity": "low", "message": "与代码无关的文件。", "remediation": "从索引移除。"},
    "HYG-013": {"title": "同一生态存在多个锁文件", "severity": "low", "message": "不同包管理器会装出不同依赖树。", "remediation": "只保留实际使用的那一个。"},
    "SCP-001": {
        "title": "依赖没有锁文件",
        "severity": "medium",
        "message": "安装结果取决于当天上游，无法复现。",
        "remediation": "生成并提交锁文件。",
    },
    "SCP-002": {
        "title": "依赖未指定版本约束",
        "severity": "medium",
        "message": "* / latest 让每次安装都可能拿到不同代码。",
        "remediation": "声明范围并提交锁文件。",
    },
    "SCP-003": {
        "title": "依赖是已知恶意包名",
        "severity": "critical",
        "message": "该包名出现在公开恶意包清单中。",
        "remediation": "立即移除并检查环境。",
    },
    "SCP-004": {
        "title": "疑似仿冒包（typosquatting）",
        "severity": "high",
        "message": "包名与流行包只差一两个字符，典型的仿冒特征。",
        "remediation": "确认包名，必要时改为正版包。",
    },
    "SCP-005": {"title": "依赖源使用明文 HTTP", "severity": "high", "message": "链路可被替换。", "remediation": "改用 HTTPS。"},
    "SCP-006": {
        "title": "依赖来自非默认源",
        "severity": "medium",
        "message": "额外源带来依赖混淆风险。",
        "remediation": "使用单一可信源并登记到策略。",
    },
    "SCP-007": {
        "title": "GitHub Action 未固定 SHA",
        "severity": "low",
        "message": "标签可被作者移动，是供应链攻击常见入口。",
        "remediation": "固定到完整 commit SHA。",
    },
    "SCP-008": {"title": "脚本中存在下载即执行", "severity": "medium", "message": "curl | bash 风险。", "remediation": "下载固定产物并校验哈希。"},
    "SCP-009": {"title": "基础镜像未固定版本", "severity": "low", "message": "每次构建内容可能不同。", "remediation": "固定 tag 或 digest。"},
    "SCP-010": {"title": "Git / 本地路径依赖", "severity": "low", "message": "不受注册表校验，漏洞库也查不到。", "remediation": "固定到具体 commit。"},
    "SCP-011": {"title": "package.json 定义了安装期脚本", "severity": "info", "message": "安装期脚本是供应链攻击主要入口。", "remediation": "确认来源可信。"},
    "SCP-012": {
        "title": "pull_request_target 里检出了 PR 代码",
        "severity": "high",
        "message": "PR 代码会在持有 secrets 与写权限的上下文里执行。",
        "remediation": "改用 pull_request，或把检出与执行拆到无密钥的 job。",
    },
    "SCP-013": {
        "title": "工作流授予了 write-all 权限",
        "severity": "medium",
        "message": "GITHUB_TOKEN 的全部写权限被交给该工作流。",
        "remediation": "按最小权限显式声明 permissions。",
    },
    "FOS-001": {
        "title": "多包仓库未限制 FOSSA 分析范围",
        "severity": "medium",
        "category": "license",
        "message": "没有 paths.only / targets.only 时，所有清单目录会被并进同一个项目。",
        "remediation": "在 .fossa.yml 中用 paths.only 限定真实交付的目录。",
    },
    "FOS-002": {
        "title": "vendored / 依赖目录没有从 FOSSA 扫描中排除",
        "severity": "medium",
        "category": "license",
        "message": "第三方代码目录会被当作第一方源码扫描，许可证条目被放大。",
        "remediation": "用 paths.exclude 排除，或改用 vendored-dependencies 显式声明。",
    },
    "FOS-003": {
        "title": "fossa-deps 条目不合规",
        "severity": "medium",
        "category": "supply",
        "message": "缺字段、类型不支持或路径不存在时，FOSSA 会静默跳过这些依赖。",
        "remediation": "补齐 type / name / version / license，并确认 vendored 路径存在。",
    },
    "FOS-004": {
        "title": "CI 只上传 FOSSA 分析结果，没有门禁",
        "severity": "medium",
        "category": "supply",
        "message": "fossa analyze 不返回失败，合规问题会直接合并。",
        "remediation": "在 analyze 之后加 fossa test（可用 --diff 只看新增问题）。",
    },
    "FOS-005": {
        "title": "FOSSA 配置无法解析或版本过旧",
        "severity": "low",
        "category": "hygiene",
        "message": "配置结构不被 FOSSA CLI v3 识别时，配置会静默失效。",
        "remediation": "迁移到 version: 3 的字段结构。",
    },
    "FOS-006": {
        "title": "FOSSA SBOM 与本地许可证结论不一致",
        "severity": "medium",
        "category": "license",
        "message": "两边判定不同，说明其中一方数据过期或识别错误。",
        "remediation": "以依赖仓库的 LICENSE 原文为准，并把结论写入 license.exceptions。",
    },
    "FOS-007": {
        "title": "FOSSA SBOM 可以补全本地无法确定的许可证",
        "severity": "info",
        "category": "license",
        "message": "该依赖本地查不到许可证，但 SBOM 里有结论。",
        "remediation": "核对后登记到 license.exceptions，避免重复提示。",
    },
    "FOS-008": {
        "title": "SBOM 里有本地没有解析到的组件",
        "severity": "info",
        "category": "license",
        "message": "这些组件只出现在 SBOM 里，通常是 vendored 代码、私有包或尚未支持的清单格式。",
        "remediation": "用 vendored-dependencies 显式声明，或为该清单格式补解析器。",
    },
    "IGN-001": {"title": "豁免已过期", "severity": "medium", "message": "豁免超出有效期。", "remediation": "修复问题或重新登记。"},
    "IGN-002": {"title": "致命问题不允许被豁免", "severity": "high", "message": "必须本次修复。", "remediation": "轮换凭据或移除恶意依赖。"},
}


def catalog() -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    for rule in secrets.SECRET_RULES:
        entries[str(rule["id"])] = {
            "title": f"疑似泄漏：{rule['name']}",
            "severity": str(rule["severity"]),
            "category": "secrets",
            "message": "匹配到已知凭据格式。",
            "remediation": str(rule["remediation"]),
        }
    for rule in ai_patterns.AI_PATTERNS:
        entries[str(rule["id"])] = {
            "title": str(rule["title"]),
            "severity": str(rule["severity"]),
            "category": "ai",
            "message": str(rule["message"]),
            "remediation": str(rule["remediation"]),
        }
    for rule in ai_patterns.ENGINEERING_LOOP_RULES:
        entries[str(rule["id"])] = {
            "title": str(rule["title"]),
            "severity": str(rule["severity"]),
            "category": "ai",
            "message": str(rule["message"]),
            "remediation": str(rule["remediation"]),
        }
    for rule in security_patterns.SECURITY_PATTERNS:
        entries[str(rule["id"])] = {
            "title": str(rule["title"]),
            "severity": str(rule["severity"]),
            "category": "security",
            "message": str(rule["message"]),
            "remediation": str(rule["remediation"]),
            "cwe": str(rule["cwe"]),
            "owasp": str(rule["owasp"]),
        }
    entries.setdefault(str(security_patterns.ACTIONS_INJECTION["id"]), {
        "title": str(security_patterns.ACTIONS_INJECTION["title"]),
        "severity": str(security_patterns.ACTIONS_INJECTION["severity"]),
        "category": "security",
        "message": str(security_patterns.ACTIONS_INJECTION["message"]),
        "remediation": str(security_patterns.ACTIONS_INJECTION["remediation"]),
        "cwe": str(security_patterns.ACTIONS_INJECTION["cwe"]),
        "owasp": str(security_patterns.ACTIONS_INJECTION["owasp"]),
    })
    for rule_id, item in MANUAL.items():
        entry = entries.setdefault(rule_id, {})
        entry.update(item)
        entry.setdefault("category", _category_of(rule_id))
    return entries


def _category_of(rule_id: str) -> str:
    manual = MANUAL.get(rule_id) or {}
    declared = str(manual.get("category") or "")
    if declared in CATEGORIES:
        return declared
    prefix = rule_id.split("-")[0]
    return {
        "SEC": "secrets",
        "AI": "ai",
        "VUL": "security",
        "DEP": "dependency",
        "LIC": "license",
        "SCP": "supply",
        "HYG": "hygiene",
        "PII": "pii",
        "FOS": "license",
        "IGN": "hygiene",
    }.get(prefix, "hygiene")


def category_label(rule_id: str) -> str:
    return CATEGORIES.get(_category_of(rule_id), "仓库卫生")
