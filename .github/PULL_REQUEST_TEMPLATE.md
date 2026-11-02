## 这个 PR 做了什么

<!-- 一句话说明问题与方案；关联 issue 用 "Closes #123" -->

## 验证方式

```bash
python -m unittest discover -s tests
python -m provemark scan . --offline --fail-on high
# 插件改动
node plugin/provemark-dsh/scripts/validate.mjs
node plugin/provemark-dsh/scripts/selftest.mjs
node plugin/provemark-dsh/scripts/sync-vendor.mjs --check
```

## 风险与回滚

<!-- 是否改动扫描行为/评分/规则 ID？是否涉及迁移或配置变更？如何回滚？ -->

## 检查清单

- [ ] 新增/修改行为有测试；`AI-0xx`/`VUL-0xx` 规则改动附带正例与反例
- [ ] 改过仓库根 `provemark/**` 后已跑 `sync-vendor.mjs`
- [ ] 没有提交密钥、真实 PII、构建产物（`dist/`、`*.tgz`）
- [ ] 对外行为变化已更新 README / CHANGELOG
- [ ] 自检无新增 critical/high（`provemark_guard` 的 `trend`）
