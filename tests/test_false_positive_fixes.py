"""真实项目暴露出的误报回归。

背景：工具在 sindresorhus/slugify、psf/requests、tiangolo/fastapi 上暴露了
五类误报——文件名带 .npmrc 就被判成凭据泄漏、PyPI 分类器里的 "BSD License"
被当成未知许可证、.github/security.md 看不见、只写 package-lock=false 的
.npmrc 被当成私钥、URL 里的 19 位业务 ID 被当成银行卡。

误报比漏报更伤信任：这些规则必须既不放过真问题，也不冤枉正常仓库。
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from provemark.cache import Cache
from provemark.config import load_config
from provemark.rules import license_data
from provemark.scanners import deps, files as files_scanner, pii, repo
from provemark.scanners.base import Context


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def context_for(root: Path) -> Context:
    config = load_config(root)
    collected, _ = files_scanner.collect_files(root, config)
    return Context(
        root=root,
        config=config,
        files=collected,
        deps=deps.collect(root, config),
        cache=Cache(enabled=False),
    )


def rules_of(findings, *rule_ids: str) -> dict[str, object]:
    wanted = set(rule_ids)
    return {item.rule_id: item for item in findings if item.rule_id in wanted}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()


class GitBase(Base):
    """需要「已提交文件」视角的用例（HYG-007 只看 Git 索引里的文件）。"""

    def setUp(self) -> None:
        super().setUp()
        if shutil.which("git") is None:
            self.skipTest("需要 git")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)

    def track(self) -> None:
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)

    def scan_repo(self):
        self.track()
        return repo.scan(context_for(self.root))


class CredentialFileTests(GitBase):
    """缺陷 1：文件名叫 .npmrc 不等于凭据泄漏。"""

    def setUp(self) -> None:
        super().setUp()
        write(self.root, "README.md", "# demo\n")
        write(self.root, "LICENSE", "MIT License\n")

    def test_npmrc_without_credentials_is_not_reported(self) -> None:
        """sindresorhus/slugify 的 .npmrc 只有 package-lock=false。"""
        write(self.root, ".npmrc", "package-lock=false\n")
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertEqual(found, {}, "普通 npm 配置不是凭据泄漏")

    def test_npmrc_with_auth_token_is_reported(self) -> None:
        write(self.root, ".npmrc", "_authToken=npm_abc123SECRETVALUE\n")
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertIn("HYG-007", found, "写了 _authToken 的 .npmrc 必须报出来")
        self.assertEqual(found["HYG-007"].severity, "critical")  # type: ignore[union-attr]

    def test_npmrc_with_auth_is_reported(self) -> None:
        write(self.root, ".npmrc", "//registry.npmjs.org/:_auth=YWJjZGVm\n")
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertIn("HYG-007", found, "写了 _auth 的 .npmrc 必须报出来")

    def test_private_key_file_is_still_reported(self) -> None:
        write(self.root, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n")
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertIn("HYG-007", found, "私钥文件无条件报出")

    def test_pem_suffix_is_still_reported(self) -> None:
        write(self.root, "server.pem", "-----BEGIN PRIVATE KEY-----\n")
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertIn("HYG-007", found, "私钥后缀无条件报出")

    def test_pypirc_with_password_is_reported(self) -> None:
        write(self.root, ".pypirc", "[pypi]\nusername = someone\npassword = s3cret\n")
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertIn("HYG-007", found, "带密码的 .pypirc 必须报出来")

    def test_pypirc_without_password_is_not_reported(self) -> None:
        write(self.root, ".pypirc", "[pypi]\nusername = someone\n")
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertEqual(found, {}, "只有用户名的 .pypirc 不是凭据泄漏")

    def test_credentials_json_without_secret_is_not_reported(self) -> None:
        write(self.root, "credentials.json", '{"endpoint": "https://api.example.com"}\n')
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertEqual(found, {}, "没有密钥的 credentials.json 不是凭据泄漏")

    def test_credentials_json_with_token_is_reported(self) -> None:
        write(self.root, "credentials.json", '{"api_key": "AKIAIOSFODNN7EXAMPLE"}\n')
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertIn("HYG-007", found, "带 api_key 的 credentials.json 必须报出来")

    def test_service_account_with_private_key_is_reported(self) -> None:
        write(
            self.root,
            "service-account.json",
            '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----"}\n',
        )
        found = rules_of(self.scan_repo(), "HYG-007")
        self.assertIn("HYG-007", found, "带 private_key 的 service-account.json 必须报出来")


class SecurityPolicyTests(Base):
    """缺陷 3：安全披露文件不一定叫 SECURITY.md。"""

    def test_lowercase_security_md_in_github_dir_is_found(self) -> None:
        """sindresorhus/slugify 的安全策略放在 .github/security.md。"""
        write(self.root, "README.md", "# demo\n")
        write(self.root, ".github/security.md", "Report issues to security@example.com\n")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-003")
        self.assertEqual(found, {}, ".github/security.md 也是安全披露渠道")

    def test_root_security_txt_is_found(self) -> None:
        write(self.root, "README.md", "# demo\n")
        write(self.root, "SECURITY.txt", "Mail security@example.com\n")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-003")
        self.assertEqual(found, {}, "SECURITY.txt 也是安全披露渠道")

    def test_missing_security_policy_is_still_reported(self) -> None:
        write(self.root, "README.md", "# demo\n")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-003")
        self.assertIn("HYG-003", found, "真的没有安全策略时仍要报出来")


class TestFileDetectionTests(Base):
    """缺陷 4：测试文件名比 tests/ 目录写法多得多。"""

    def test_test_js_counts_as_test(self) -> None:
        """sindresorhus/slugify 的 npm test 跑的是 node --test，入口是 test.js。"""
        write(self.root, "README.md", "# demo\n")
        write(self.root, "test.js", "import test from 'node:test';\n")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-011")
        self.assertEqual(found, {}, "test.js 就是测试文件")

    def test_test_prefixed_file_counts_as_test(self) -> None:
        write(self.root, "README.md", "# demo\n")
        write(self.root, "test-utils.ts", "export const helper = 1;\n")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-011")
        self.assertEqual(found, {}, "test-*.ts 也是测试文件")

    def test_repo_without_tests_is_still_reported(self) -> None:
        write(self.root, "README.md", "# demo\n")
        write(self.root, "index.js", "export default 1;\n")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-011")
        self.assertIn("HYG-011", found, "真的没有测试时仍要报出来")


class LicenseAliasTests(Base):
    """缺陷 2：PyPI 分类器里的许可证写法必须认得出来。"""

    def test_pypi_classifier_license_is_recognised(self) -> None:
        self.assertEqual(
            license_data.normalize_spdx("License :: OSI Approved :: BSD License"),
            "BSD-3-Clause",
        )

    def test_common_metadata_licenses_are_recognised(self) -> None:
        cases = {
            "BSD License": "BSD-3-Clause",
            "Apache Software License": "Apache-2.0",
            "MIT License": "MIT",
            "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
            "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
            "GNU Lesser General Public License v2.1 (LGPLv2.1)": "LGPL-2.1-only",
            "GNU Affero General Public License v3 (AGPLv3)": "AGPL-3.0-only",
        }
        for raw, expected in cases.items():
            self.assertEqual(license_data.normalize_spdx(raw), expected, raw)

    def test_known_licenses_are_not_unknown(self) -> None:
        policy = load_config(self.root).license_policy
        status, effective = license_data.evaluate(
            "License :: OSI Approved :: BSD License", policy
        )
        self.assertNotEqual(status, "unknown", "BSD 是已知许可证")
        self.assertEqual(effective, ["BSD-3-Clause"])

    def test_gpl_classifier_is_not_unknown(self) -> None:
        policy = load_config(self.root).license_policy
        status, effective = license_data.evaluate(
            "License :: OSI Approved :: GNU General Public License v3 (GPLv3)", policy
        )
        self.assertNotEqual(status, "unknown", "GPLv3 是已知许可证")
        self.assertEqual(effective, ["GPL-3.0-only"])


class CardContextTests(Base):
    """缺陷 5：Luhn 通过不等于银行卡。"""

    def cards(self):
        return [
            item for item in pii.scan(context_for(self.root)) if item.rule_id == "PII-004"
        ]

    def test_activity_id_in_url_is_not_a_card(self) -> None:
        """tiangolo/fastapi 的 README 里到处是 LinkedIn activity ID。"""
        write(
            self.root,
            "src/app.py",
            'REF = "https://www.linkedin.com/posts/deonpillsbury_cisco-cx-python-'
            'activity-6963242628536487936-trAp/"\n',
        )
        self.assertEqual(self.cards(), [], "URL 里的业务主键不是银行卡")

    def test_long_id_in_markdown_link_is_not_a_card(self) -> None:
        write(self.root, "src/app.py", "REF = '[ref](6963242628536487936)'\n")
        self.assertEqual(self.cards(), [], "markdown 链接目标里的数字不是银行卡")

    def test_number_in_file_path_is_not_a_card(self) -> None:
        write(self.root, "src/app.py", "PATH = 'data/4532015112830366.json'\n")
        self.assertEqual(self.cards(), [], "文件路径里的数字不是银行卡")

    def test_commit_sha_is_not_a_card(self) -> None:
        write(self.root, "src/app.py", "SHA = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b'\n")
        self.assertEqual(self.cards(), [], "commit SHA 不是银行卡")

    def test_nineteen_digit_id_is_not_a_card(self) -> None:
        write(self.root, "src/app.py", "ORDER_ID = 6963242628536487936\n")
        self.assertEqual(self.cards(), [], "19 位数字更像业务 ID")

    def test_real_card_is_still_reported(self) -> None:
        write(self.root, "src/pay.py", 'CARD = "4532015112830366"\n')
        found = self.cards()
        self.assertEqual(len(found), 1, "真实卡号必须报出来")
        self.assertEqual(found[0].severity, "high")

    def test_official_test_card_is_still_downgraded(self) -> None:
        write(self.root, "src/pay.py", 'CARD = "4242 4242 4242 4242"\n')
        found = self.cards()
        self.assertEqual(len(found), 1, "官方测试卡号仍要报出来")
        self.assertEqual(found[0].severity, "low")
        self.assertTrue(found[0].detail["test_card"])


if __name__ == "__main__":
    unittest.main()
