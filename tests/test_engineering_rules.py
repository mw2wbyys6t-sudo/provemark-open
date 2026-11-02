"""全栈工程规则（AI-015 ~ AI-020）的回归测试。

覆盖 AI 生成代码最典型的后端/前端工程缺陷：请求没超时、循环里串行 await、
N+1 查询、ORM 自动改库、Django 放开主机/CORS、print 当日志。每条都有正例、
反例与降级用例——工程规则最容易变成“正确但吵闹”。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from provemark.cache import Cache
from provemark.config import load_config
from provemark.rules.catalog import catalog
from provemark.scanners import ai_code, deps, files as files_scanner
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


class EngineeringRuleCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def rules_hit(self) -> set[str]:
        return {item.rule_id for item in ai_code.scan(context_for(self.root))}

    def assert_rule(self, rel: str, content: str, rule_id: str) -> None:
        write(self.root, rel, content)
        self.assertIn(rule_id, self.rules_hit(), f"{rule_id} 应该命中：{content}")

    def assert_clean(self, rel: str, content: str, rule_id: str) -> None:
        write(self.root, rel, content)
        self.assertNotIn(rule_id, {item.rule_id for item in ai_code.scan(context_for(self.root))})


class RequestTimeoutTests(EngineeringRuleCase):
    def test_requests_without_timeout(self) -> None:
        self.assert_rule("app.py", "requests.get(url)\n", "AI-015")

    def test_requests_with_timeout_is_clean(self) -> None:
        self.assert_clean("app.py", "requests.get(url, timeout=5)\n", "AI-015")

    def test_fetch_without_signal(self) -> None:
        self.assert_rule("src/api.js", "const r = await fetch(url);\n", "AI-015")

    def test_fetch_with_signal_is_clean(self) -> None:
        self.assert_clean("src/api.js", "const r = await fetch(url, { signal: AbortSignal.timeout(5000) });\n", "AI-015")

    def test_axios_without_timeout(self) -> None:
        self.assert_rule("src/api.ts", "const r = await axios.get(url);\n", "AI-015")


class LoopTests(EngineeringRuleCase):
    def test_sequential_await_in_loop(self) -> None:
        self.assert_rule(
            "src/jobs.py",
            "async def run(ids):\n    for uid in ids:\n        await fetch(uid)\n",
            "AI-016",
        )

    def test_loop_without_await_is_clean(self) -> None:
        self.assert_clean(
            "src/jobs.py",
            "async def run(ids):\n    for uid in ids:\n        print(uid)\n",
            "AI-016",
        )

    def test_dynamic_import_loop_is_clean(self) -> None:
        self.assert_clean(
            "src/loader.js",
            "export async function load(list) {\n  for (const item of list) {\n    await import(item);\n  }\n}\n",
            "AI-016",
        )

    def test_n_plus_one(self) -> None:
        self.assert_rule(
            "app/views.py",
            "def list_orders(users):\n    for user in users:\n        Order.objects.filter(user=user)\n",
            "AI-017",
        )

    def test_async_loop_counts_as_await_not_n_plus_one(self) -> None:
        write(
            self.root,
            "app/views.py",
            "async def list_orders(users):\n    for user in users:\n        await Order.objects.aget(user=user)\n",
        )
        hit = self.rules_hit()
        self.assertIn("AI-016", hit)
        self.assertNotIn("AI-017", hit, "异步循环已经由 AI-016 覆盖，不重复报 N+1")

    def test_plain_find_in_loop_is_clean(self) -> None:
        self.assert_clean(
            "src/text.js",
            "export function scan(lines) {\n  for (const line of lines) {\n    const at = line.find('x');\n  }\n}\n",
            "AI-017",
        )


class OrmConfigTests(EngineeringRuleCase):
    def test_typeorm_synchronize(self) -> None:
        self.assert_rule("src/db.ts", "const db = new DataSource({ synchronize: true });\n", "AI-018")

    def test_typeorm_synchronize_false_is_clean(self) -> None:
        self.assert_clean("src/db.ts", "const db = new DataSource({ synchronize: false });\n", "AI-018")

    def test_django_wildcard_hosts(self) -> None:
        self.assert_rule("settings.py", "ALLOWED_HOSTS = ['*']\n", "AI-019")

    def test_django_explicit_hosts_is_clean(self) -> None:
        self.assert_clean("settings.py", "ALLOWED_HOSTS = ['api.example.com']\n", "AI-019")

    def test_cors_allow_all(self) -> None:
        self.assert_rule("settings.py", "CORS_ALLOW_ALL_ORIGINS = True\n", "AI-019")


class LoggingTests(EngineeringRuleCase):
    def test_print_as_log_in_app_code(self) -> None:
        self.assert_rule("src/service.py", "def handle(x):\n    print('debug', x)\n", "AI-020")

    def test_print_in_cli_is_clean(self) -> None:
        self.assert_clean("src/cli.py", "print('usage: app <cmd>')\n", "AI-020")

    def test_print_in_tests_is_skipped(self) -> None:
        """测试代码不参与工程规则：测试里的 print 是合法诊断输出。"""
        write(self.root, "tests/test_x.py", "print('debug')\n")
        items = [item for item in ai_code.scan(context_for(self.root)) if item.rule_id == "AI-020"]
        self.assertEqual(items, [])


class AlgorithmTests(EngineeringRuleCase):
    def test_sync_http_calls_in_loop(self) -> None:
        self.assert_rule(
            "src/batch.py",
            "def fetch_all(ids):\n    for uid in ids:\n        requests.get('/api/' + uid)\n",
            "AI-021",
        )

    def test_async_loop_is_await_not_sync_io(self) -> None:
        write(
            self.root,
            "src/batch.py",
            "async def fetch_all(ids):\n    for uid in ids:\n        await fetch(uid)\n",
        )
        hit = self.rules_hit()
        self.assertIn("AI-016", hit)
        self.assertNotIn("AI-021", hit, "异步循环由 AI-016 覆盖，不重复报同步 IO")

    def test_string_concat_in_loop(self) -> None:
        self.assert_rule(
            "src/report.py",
            "def render(rows):\n    msg = ''\n    for row in rows:\n        msg += 'line'\n    return msg\n",
            "AI-022",
        )

    def test_numeric_accumulation_is_clean(self) -> None:
        self.assert_clean(
            "src/count.py",
            "def count(rows):\n    total = 0\n    for row in rows:\n        total += 1\n    return total\n",
            "AI-022",
        )

    def test_dataframe_concat_in_loop(self) -> None:
        self.assert_rule(
            "src/etl.py",
            "def merge(parts):\n    frames = []\n    for part in parts:\n        frames.append(pd.concat([part]))\n",
            "AI-024",
        )

    def test_list_queue_pop_zero(self) -> None:
        self.assert_rule("src/queue.py", "while items:\n    items.pop(0)\n", "AI-025")

    def test_deque_is_clean(self) -> None:
        self.assert_clean("src/queue.py", "while items:\n    items.popleft()\n", "AI-025")

    def test_iterrows(self) -> None:
        self.assert_rule("src/etl.py", "for _, row in df.iterrows():\n    handle(row)\n", "AI-026")


class CatalogTests(unittest.TestCase):
    def test_engineering_rules_are_documented(self) -> None:
        entries = catalog()
        for rule_id in ("AI-015", "AI-016", "AI-017", "AI-018", "AI-019", "AI-020"):
            self.assertIn(rule_id, entries)
            self.assertEqual(entries[rule_id]["category"], "ai")
            self.assertTrue(entries[rule_id]["title"])
            self.assertTrue(entries[rule_id]["remediation"])

    def test_algorithm_rules_are_documented(self) -> None:
        entries = catalog()
        for rule_id in ("AI-021", "AI-022", "AI-024", "AI-025", "AI-026"):
            self.assertIn(rule_id, entries)
            self.assertEqual(entries[rule_id]["category"], "ai")
            self.assertTrue(entries[rule_id]["title"])


if __name__ == "__main__":
    unittest.main()
