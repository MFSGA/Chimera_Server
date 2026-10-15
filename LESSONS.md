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
| — | — | — | 尚无经本流程确认的记录 | — | — |

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

*尚无经过上述证据要求确认并收录的新记录。已有历史事故与实施证据继续以 `ARCHITECTURE.md`、`ITERATION_GUIDE.md`、实际 PR/CI 为准，不在此虚构。*
