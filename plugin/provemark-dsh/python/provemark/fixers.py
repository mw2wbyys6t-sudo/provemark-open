from __future__ import annotations

import contextlib
import datetime as dt
import json
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .config import DEFAULT_CONFIG_TEMPLATE, Config, find_config_file
from .models import ScanResult
from .rules import license_data
from .rules.license_texts import APACHE2_TEXT

LICENSE_FILE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING")

# `fix --only` 的可选范围。放在模块级，CLI 才能在执行前校验用户输入，
# 避免拼错时静默地什么都不做。
FIX_TARGETS = {
    "license": "LICENSE",
    "gitignore": ".gitignore",
    "security": "SECURITY.md",
    "config": ".provemark.toml",
    "ci": ".github/workflows",
}

MIT_TEXT = """MIT License

Copyright (c) {year} {holder}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

BSD3_TEXT = """BSD 3-Clause License

Copyright (c) {year}, {holder}

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

UNLICENSE_TEXT = """This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""

REMOTE_LICENSE_URLS = {
    "Apache-2.0": "https://www.apache.org/licenses/LICENSE-2.0.txt",
    "MPL-2.0": "https://www.mozilla.org/media/MPL/2.0/index.815ca599c9df.txt",
}

SECURITY_TEMPLATE = """# 安全政策

## 报告漏洞

请不要通过公开 issue 报告安全问题。请使用 GitHub 仓库的 **Security → Report a vulnerability**
私下提交，或通过仓库主页列出的维护者邮箱联系。

报告中请包含：

- 受影响的版本或提交范围
- 复现步骤或最小复现样例
- 影响评估（能读到什么、能执行什么）
- 可选：修复建议

## 响应约定

- 3 个工作日内确认收到报告
- 30 天内给出修复或缓解方案
- 修复发布后会在 CHANGELOG 中说明（如需匿名请提前告知）

## 范围

本政策适用于本仓库的源代码与官方发布的构建产物。第三方依赖自身的漏洞请直接反馈给上游项目。
"""

CI_TEMPLATE = """name: provemark

on:
  push:
    branches: [main, master]
  pull_request:
  schedule:
    - cron: "0 3 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      # 默认从源码仓库安装（官方包尚未发布到 PyPI）。
      # 如果你把 Provemark 发布到了 PyPI，把下面这行改成 "provemark" 即可。
      PROVEMARK_SPEC: "git+https://github.com/mw2wbyys6t-sudo/provemark-open@v0.6.2"
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: "3.12"
      - name: Install scanner
        run: pip install "$PROVEMARK_SPEC"
      - name: Scan
        run: provemark scan --fail-on high --min-confidence 0.5 --format sarif -o provemark.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
        with:
          sarif_file: provemark.sarif
"""

GITIGNORE_LINES = [
    "# 环境变量与密钥",
    ".env",
    ".env.*",
    "!.env.example",
    "*.pem",
    "*.key",
    "",
    "# 依赖与缓存",
    "node_modules/",
    "__pycache__/",
    "*.pyc",
    ".venv/",
    "venv/",
    "",
    "# 构建产物",
    "dist/",
    "build/",
    "*.egg-info/",
    ".next/",
    "target/",
    "",
    "# 系统与编辑器",
    ".DS_Store",
    "Thumbs.db",
    ".idea/",
    ".vscode/",
    "",
    "# 扫描产物",
    "provemark-report.html",
    "provemark.sarif",
]

HOOK_TEMPLATE = """#!/bin/sh
# 由 Provemark 生成：提交前只扫描暂存区，命中高危及以上则阻止提交
# 扫描器不可用时只提示、不阻止提交（避免把开发卡死）
if ! "{python}" -c "import provemark" >/dev/null 2>&1; then
  echo "[provemark] 未安装，跳过本次检查（pip install provemark 后生效）" >&2
  exit 0
fi
exec "{python}" -m provemark scan --staged --fail-on high --quiet
"""


@dataclass
class Action:
    kind: str
    path: str
    description: str
    content: str = ""
    lines: list[str] = field(default_factory=list)
    skipped: str = ""

    def summary(self) -> str:
        if self.skipped:
            return f"跳过 {self.path}：{self.skipped}"
        if self.kind == "append":
            return f"追加 {self.path}（{len(self.lines)} 行）"
        return f"创建 {self.path}"


def git_user(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "config", "user.name"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def fetch_license_text(spdx: str, timeout: float = 20.0) -> str:
    url = REMOTE_LICENSE_URLS.get(spdx)
    if not url:
        return ""
    try:
        import urllib.request

        request = urllib.request.Request(url, headers={"User-Agent": f"provemark/{__version__}"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def license_text(spdx: str, holder: str, year: int, *, offline: bool = False, timeout: float = 20.0) -> str:
    holder = holder or "<版权所有者>"
    if spdx == "MIT":
        return MIT_TEXT.format(year=year, holder=holder)
    if spdx == "BSD-3-Clause":
        return BSD3_TEXT.format(year=year, holder=holder)
    if spdx == "Unlicense":
        return UNLICENSE_TEXT
    if spdx in ("Apache-2.0", "Apache-2.0-only"):
        return APACHE2_TEXT
    if offline:
        return ""
    return fetch_license_text(spdx, timeout=timeout)


def _detect_project_license(root: Path) -> str:
    """从根目录的 LICENSE / 清单文件推断项目许可证，避免策略文件写错。"""
    for name in LICENSE_FILE_NAMES:
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        spdx = license_data.detect_from_text(text)
        if spdx:
            return spdx

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            payload = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            payload = {}
        candidates = [
            (payload.get("project") or {}).get("license"),
            ((payload.get("tool") or {}).get("poetry") or {}).get("license"),
        ]
        for value in candidates:
            if isinstance(value, dict):
                value = value.get("text")
            if isinstance(value, str) and value.strip():
                spdx = license_data.normalize_spdx(value)
                if spdx:
                    return spdx

    package_json = root / "package.json"
    if package_json.is_file():
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        value = payload.get("license")
        if isinstance(value, dict):
            value = value.get("type")
        if isinstance(value, str) and value.strip():
            spdx = license_data.normalize_spdx(value)
            if spdx:
                return spdx

    cargo = root / "Cargo.toml"
    if cargo.is_file():
        try:
            payload = tomllib.loads(cargo.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            payload = {}
        value = (payload.get("package") or {}).get("license")
        if isinstance(value, str) and value.strip():
            spdx = license_data.normalize_spdx(value)
            if spdx:
                return spdx
    return ""


def plan(
    root: Path,
    config: Config,
    result: ScanResult | None = None,
    *,
    license_id: str = "",
    holder: str = "",
    include_ci: bool = True,
    only: list[str] | None = None,
) -> list[Action]:
    actions: list[Action] = []
    declared = license_id or config.project_license or _detect_project_license(root)
    holder = holder or git_user(root)

    has_license = any((root / name).exists() for name in LICENSE_FILE_NAMES)
    spdx = declared or ("" if has_license or config.project_kind == "docs" else "Apache-2.0")
    if not has_license and config.project_kind != "docs":
        content = license_text(spdx, holder, dt.date.today().year)
        if content:
            actions.append(
                Action(
                    kind="create",
                    path="LICENSE",
                    description=f"添加 {spdx} 许可证全文（版权所有者：{holder or '待填写'}）",
                    content=content,
                )
            )
        else:
            actions.append(
                Action(
                    kind="create",
                    path="LICENSE",
                    description=f"添加 {spdx} 许可证",
                    skipped="无法联网获取该许可证全文，请手动添加（或改选 MIT / BSD-3-Clause）",
                )
            )

    gitignore = root / ".gitignore"
    if gitignore.is_file():
        existing = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        existing_set = {line.strip() for line in existing}
        missing = [line for line in GITIGNORE_LINES if line and line not in existing_set and not line.startswith("#")]
        if missing:
            actions.append(
                Action(
                    kind="append",
                    path=".gitignore",
                    description="补充 .env / 依赖 / 产物等忽略规则",
                    lines=[""] + ["# 由 Provemark 补充"] + missing,
                )
            )
    else:
        actions.append(
            Action(
                kind="create",
                path=".gitignore",
                description="创建覆盖密钥、依赖与构建产物的 .gitignore",
                content="\n".join(GITIGNORE_LINES) + "\n",
            )
        )

    if not (root / "SECURITY.md").exists() and config.project_kind != "docs":
        actions.append(
            Action(
                kind="create",
                path="SECURITY.md",
                description="创建安全披露政策",
                content=SECURITY_TEMPLATE,
            )
        )

    if find_config_file(root) is None:
        content = DEFAULT_CONFIG_TEMPLATE
        if spdx:
            content = content.replace('license = ""', f'license = "{spdx}"')
        actions.append(
            Action(
                kind="create",
                path=".provemark.toml",
                description="创建扫描策略文件（可后续调整门禁与许可证白名单）",
                content=content,
            )
        )

    if include_ci and not (root / ".github" / "workflows").exists():
        actions.append(
            Action(
                kind="create",
                path=".github/workflows/provemark.yml",
                description="创建 GitHub Actions 工作流（扫描 + SARIF 上传）",
                content=CI_TEMPLATE,
            )
        )

    if only:
        wanted = [FIX_TARGETS.get(token, token) for token in only]
        actions = [
            action for action in actions if any(action.path.startswith(path) for path in wanted)
        ]
    return actions


def apply_action(root: Path, action: Action, *, force: bool = False) -> str:
    if action.skipped:
        return f"跳过 {action.path}"
    target = root / action.path
    # A repository can ship `.gitignore -> ~/.bashrc`, or a dangling symlink where
    # the fixer wants to create a file. Writing through either would edit a file
    # outside the project — the one thing a "safe fixer" must never do.
    root_path = Path(root)
    try:
        relative_parent = target.parent.relative_to(root_path)
    except ValueError:
        return f"跳过 {action.path}（目标越界）"
    probe = root_path
    for part in relative_parent.parts:
        probe = probe / part
        if probe.is_symlink():
            return f"跳过 {action.path}（路径包含符号链接 {part}）"
    if target.is_symlink():
        return f"跳过 {action.path}（目标本身是符号链接）"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if action.kind == "create":
            if target.exists() and not force:
                return f"跳过 {action.path}（已存在）"
            target.write_text(action.content, encoding="utf-8")
            return f"已创建 {action.path}"
        with target.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(action.lines) + "\n")
        return f"已追加 {action.path}"
    except OSError as exc:
        return f"失败 {action.path}：{exc}"


def install_hook(root: Path, *, force: bool = False) -> str:
    import sys

    hook = root / ".git" / "hooks" / "pre-commit"
    if not (root / ".git").exists():
        return "当前目录不是 Git 仓库，无法安装钩子"
    if hook.exists() and not force:
        return f"{hook} 已存在，使用 --force 覆盖"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK_TEMPLATE.format(python=sys.executable), encoding="utf-8")
    with contextlib.suppress(OSError):
        hook.chmod(0o755)
    return f"已安装 pre-commit 钩子：{hook}"


def uninstall_hook(root: Path) -> str:
    hook = root / ".git" / "hooks" / "pre-commit"
    if not hook.exists():
        return "没有找到 pre-commit 钩子"
    try:
        content = hook.read_text(encoding="utf-8", errors="replace")
    except OSError:
        content = ""
    if "Provemark" not in content:
        return "现有钩子不是 Provemark 生成的，未删除"
    hook.unlink()
    return f"已移除钩子：{hook}"


def ensure_git_available() -> bool:
    return shutil.which("git") is not None
