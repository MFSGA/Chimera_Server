# Engineering Lessons — Chimera Server

此文件是 AI 与维护者共用的**可验证经验库**，不是架构替代品、缺陷清单或自动调整权限的依据。

- 开始任何行为变更前检索与受影响模块相关的 Lessons；没有相关条目时按 `AGENTS.md` 工作即可。
- 只记录**有证据的已发生问题**。未解决问题、猜测、待验证方案归入 Issue / 设计文档，不能冒充已确认根因。
- 新条目要求：日期、对应 Issue/PR/commit/CI、复现/影响、根因、预防措施、可执行的回归验证、状态。
- 不粘贴密码、密钥、认证负载、完整运行配置、私人数据；日志先脱敏。
- 重复问题可提议强化 `docs/ai-development-governance.md` 或 `AGENTS.md`，但**修改制度需要维护者审查**，不能以 AI 复盘直接放宽 CI。
- 不从过往提交次数推断已通过测试，不把没跑的 ignored 用例当已验证。

## 索引

| ID | 日期 | 模块 | 问题 | 状态 | 证据 |
| --- | --- | --- | --- | --- | --- |
| LESSON-20261015-001 | 2026-10-15 | Workflow | 自动合并预检把 Actions jobs 响应误判为列表 | Mitigated locally; remote verification pending | [Auto-merge run 38738346030](https://github.com/MFSGA/Chimera_Server/actions/runs/38738346030) |

## 记录模板（复制后填写；不要将空白模板当作事故记录）

```markdown
### LESSON-YYYYMMDD-001: 简明标题
- 发现日期（UTC）：
- 分类：Protocol / Security / Lifecycle / Config / Platform / CI / Workflow / Release
- 严重度：Critical / High / Medium / Low
- 状态：Open / Mitigated / Verified
- 证据：Issue / PR / commit / CI 运行链接或本地复现记录
- 影响范围：协议×传输×安全×TCP/UDP / feature / 平台（若适用）
- 观察到的失败：预期行为 / 实际行为
- 根本原因：由什么证据支持？仍有什么不确定性？
- 修复措施：变更路径或提交
- 预防措施：规范、测试、静态检查、审查清单
- 回归验证：命令、环境、Xray/client 版本、结果
- 重复事件：关联到其他独立事故（若有）
- 是否提议升级为强制规则：是 / 否；审批链接
```

## 已确认经验

### LESSON-20261015-001: 自动合并预检误读 GitHub Actions jobs 响应
- 发现日期（UTC）：2026-10-15
- 分类：Workflow
- 严重度：Medium
- 状态：Mitigated（本地修复；等待推送后的 CI 验证）
- 证据：[失败的 Auto-merge run 38738346030](https://github.com/MFSGA/Chimera_Server/actions/runs/38738346030)；关联 CI run 38737272211 成功，GitHub jobs 接口返回 12 个 job。
- 影响范围：`auto-merge.yml` 的 `workflow_run` 预检路径；符合现有策略的 README PR 在 CI 成功后无法进入自动合并预检。
- 观察到的失败：预期从成功 CI run 读取全部 job；实际报 `GitHub API returned an unexpected list response` 并安全退出。
- 根本原因：脚本将 `GET /actions/runs/{run_id}/jobs` 当成裸数组解析；GitHub 实际返回 `{ "total_count": ..., "jobs": [...] }` 分页对象。issue events 和 PR files 接口仍返回裸数组，不能统一假定所有列表端点具有相同外层结构。
- 修复措施：`get_all` 可按显式 `collection_key` 读取包装列表，CI jobs 使用 `jobs` 键；原有裸数组读取保持不变。
- 预防措施：CI 中的 auto-merge policy self-test 覆盖包装分页、`Link` 翻页、现有裸数组和缺失 `jobs` 字段时 fail closed。
- 回归验证：`python3 .github/scripts/auto_merge_after_ci.py --self-test`、`python3 -m py_compile .github/scripts/auto_merge_after_ci.py`、`git diff --check` 均通过；修复后远端 Actions 验证尚未执行。
- 重复事件：无已知关联事件。
- 是否提议升级为强制规则：否；现有 CI 自测足以覆盖这一具体 API 响应契约。
