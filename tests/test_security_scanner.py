"""应用层漏洞规则（VUL-*）的回归测试。

每条规则至少一个正例；另有一组“不该报”的反例（参数化 SQL、文档示例、注释、
无安全语境的 md5 校验和），因为安全扫描器的价值在于信噪比，而不是条目数。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from provemark.cache import Cache
from provemark.cli import SCANNERS
from provemark.config import load_config
from provemark.engine import SCANNER_MAP
from provemark.rules.catalog import catalog
from provemark.scanners import deps, files as files_scanner, security
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


class SecurityRuleCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def scan(self) -> dict[str, object]:
        findings = security.scan(context_for(self.root))
        return {item.rule_id: item for item in findings}

    def assert_rule(self, rel: str, content: str, rule_id: str) -> object:
        write(self.root, rel, content)
        found = self.scan()
        self.assertIn(rule_id, found, f"{rule_id} 应该命中：{content}")
        return found[rule_id]

    def assert_clean(self, rel: str, content: str) -> None:
        write(self.root, rel, content)
        self.assertEqual(self.scan(), {}, f"不应该命中：{content}")


class InjectionTests(SecurityRuleCase):
    def test_sql_string_formatting(self) -> None:
        finding = self.assert_rule(
            "app.py",
            'db.execute("SELECT * FROM t WHERE id = %s" % user_id)\n',
            "VUL-001",
        )
        self.assertEqual(finding.detail["cwe"], "CWE-89")  # type: ignore[union-attr]

    def test_sql_fstring(self) -> None:
        self.assert_rule("app.py", 'cur.execute(f"SELECT * FROM t WHERE id = {uid}")\n', "VUL-001")

    def test_sql_js_template(self) -> None:
        self.assert_rule("db.js", "db.query(`SELECT * FROM t WHERE id = ${id}`)\n", "VUL-001")

    def test_sql_go_concat(self) -> None:
        self.assert_rule(
            "main.go",
            'package main\nfunc q(db *DB, id string) {\n\tdb.Query("SELECT * FROM t WHERE id = " + id)\n}\n',
            "VUL-001",
        )

    def test_parameterized_sql_is_clean(self) -> None:
        self.assert_clean(
            "app.py",
            'db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()\n',
        )

    def test_sql_in_docstring_is_clean(self) -> None:
        self.assert_clean(
            "app.py",
            '"""Example:\n\n    db.execute("SELECT * FROM t WHERE id = %s" % uid)\n"""\nx = 1\n',
        )

    def test_command_injection(self) -> None:
        self.assert_rule(
            "app.py",
            'subprocess.run("ping " + host, shell=True)\n',
            "VUL-002",
        )

    def test_template_injection(self) -> None:
        self.assert_rule(
            "app.py",
            'render_template_string(request.args["tpl"])\n',
            "VUL-003",
        )

    def test_deserialization(self) -> None:
        self.assert_rule("app.py", "marshal.loads(payload)\n", "VUL-004")

    def test_xss_markup(self) -> None:
        self.assert_rule(
            "app.py",
            'Markup(f"<b>{request.args[\'x\']}</b>")\n',
            "VUL-005",
        )


class WebAndNetworkTests(SecurityRuleCase):
    def test_path_traversal(self) -> None:
        self.assert_rule(
            "app.py",
            'open(os.path.join("/data", request.args["file"]))\n',
            "VUL-006",
        )

    def test_ssrf(self) -> None:
        self.assert_rule("app.py", 'requests.get(request.args["url"])\n', "VUL-007")

    def test_tls_verification_disabled(self) -> None:
        for rel, line in (
            ("a.py", "ssl._create_unverified_context()\n"),
            ("a.js", "const agent = new https.Agent({ rejectUnauthorized: false });\n"),
            ("a.go", 'tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n'),
        ):
            with self.subTest(lang=rel):
                self.tearDown()
                self.setUp()
                finding = self.assert_rule(rel, line, "VUL-010")
                self.assertEqual(finding.detail["cwe"], "CWE-295")  # type: ignore[union-attr]

    def test_jwt_verification_disabled(self) -> None:
        self.assert_rule(
            "app.py",
            'jwt.decode(token, options={"verify_signature": False})\n',
            "VUL-012",
        )

    def test_xxe(self) -> None:
        self.assert_rule("app.py", "etree.XMLParser(resolve_entities=True)\n", "VUL-015")


class CryptoAndConfigTests(SecurityRuleCase):
    def test_weak_hash_only_in_security_context(self) -> None:
        finding = self.assert_rule(
            "app.py",
            "hashlib.md5(password.encode()).hexdigest()\n",
            "VUL-008",
        )
        self.assertEqual(finding.severity, "high")  # type: ignore[union-attr]

    def test_checksum_md5_is_clean(self) -> None:
        self.assert_clean("app.py", "digest = hashlib.md5(open(path, 'rb').read()).hexdigest()\n")

    def test_insecure_random_for_token(self) -> None:
        self.assert_rule("app.py", "token = random.random()\n", "VUL-009")

    def test_ecb_mode(self) -> None:
        self.assert_rule("app.py", "AES.new(key, AES.MODE_ECB)\n", "VUL-011")

    def test_insecure_cookie(self) -> None:
        self.assert_rule(
            "app.py",
            'resp.set_cookie("sid", value, secure=False, httponly=False)\n',
            "VUL-013",
        )

    def test_debug_mode(self) -> None:
        self.assert_rule("app.py", "app.run(debug=True)\n", "VUL-014")


class PlatformTests(SecurityRuleCase):
    def test_c_buffer_functions(self) -> None:
        self.assert_rule("legacy.c", "void f(char *in) { char b[8]; strcpy(b, in); }\n", "VUL-016")

    def test_actions_script_injection(self) -> None:
        self.assert_rule(
            ".github/workflows/ci.yml",
            "on: [pull_request]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n',
            "VUL-017",
        )

    def test_privileged_container(self) -> None:
        self.assert_rule(
            "docker-compose.yml",
            "services:\n  app:\n    privileged: true\n",
            "VUL-018",
        )


class BehaviourTests(SecurityRuleCase):
    def test_findings_aggregate_per_file(self) -> None:
        write(
            self.root,
            "app.py",
            'db.execute("SELECT * FROM t WHERE a = %s" % a)\ndb.execute("SELECT * FROM t WHERE b = %s" % b)\n',
        )
        found = security.scan(context_for(self.root))
        sqli = [item for item in found if item.rule_id == "VUL-001"]
        self.assertEqual(len(sqli), 1, "同一文件同一规则应聚合为一条")
        self.assertEqual(sqli[0].detail["count"], 2)

    def test_test_directory_downgrades(self) -> None:
        write(self.root, "tests/test_app.py", 'db.execute("SELECT * FROM t WHERE id = %s" % uid)\n')
        found = security.scan(context_for(self.root))
        self.assertIn("VUL-001", {item.rule_id for item in found})
        item = next(item for item in found if item.rule_id == "VUL-001")
        self.assertEqual(item.severity, "medium")
        self.assertLessEqual(item.confidence, 0.5)

    def test_go_test_file_tls_is_low(self) -> None:
        write(self.root, "server_test.go", "package x\nvar c = tls.Config{InsecureSkipVerify: true}\n")
        found = security.scan(context_for(self.root))
        item = next(item for item in found if item.rule_id == "VUL-010")
        self.assertEqual(item.severity, "low")

    def test_comments_are_ignored(self) -> None:
        self.assert_clean("app.py", "# app.run(debug=True)\nx = 1\n")

    def test_every_finding_carries_mapping(self) -> None:
        write(self.root, "app.py", "app.run(debug=True)\n")
        item = security.scan(context_for(self.root))[0]
        self.assertTrue(item.detail["cwe"].startswith("CWE-"))
        self.assertRegex(item.detail["owasp"], r"A\d{2}:2021")
        self.assertTrue(item.reference.startswith("https://cwe.mitre.org/"))


class RegistryTests(unittest.TestCase):
    def test_scanner_is_registered(self) -> None:
        self.assertIn("security", SCANNER_MAP)
        self.assertIn("security", SCANNERS)

    def test_catalog_maps_rules_to_security(self) -> None:
        entries = catalog()
        for rule_id in ("VUL-001", "VUL-016", "VUL-017", "VUL-018"):
            self.assertIn(rule_id, entries)
            self.assertEqual(entries[rule_id]["category"], "security", rule_id)
            self.assertTrue(entries[rule_id]["title"])


if __name__ == "__main__":
    unittest.main()
