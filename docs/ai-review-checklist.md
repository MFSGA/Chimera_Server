# Chimera Server — 独立 AI Code Review 清单

使用新 Codex 会话或不同执行上下文，从实际 PR diff、代码、CI 日志及固定 Xray 基线独立判断。开发者的自述是线索，**不是证据**。

## 阻断项（任意一项成立则 REQUEST_CHANGES）

- [ ] 变更目标、边界、风险 L0–L3 与 PR 中填写的一致；无附带重构、无未授权发布或远程操作。
- [ ] 安全：认证/重放、REALITY/TLS、secret/error/log 没有泄漏或静默绕过；敏感 unsupported 选项 fail closed。
- [ ] Xray：省略/显式/未知字段、默认值、协议帧、fallback、负向认证、TCP EOF/half-close、UDP 目标和报文、policy/metrics 等行为没有未经声明的偏差。
- [ ] 生命周期：任务 owner、取消、排空、超时、重建代次、资源回滚完整；并发与缓冲有界。
- [ ] 平台和 Cargo feature：新增 `cfg` 范围准确，默认 / 缩减 feature 不静默改变行为，Windows/Linux 必要范围覆盖。
- [ ] 测试：存在真实的通过证据；ignored 用例、客户端互通、benchmark 没有被“cargo test 成功”代替；zero tests 不算通过。
- [ ] 兼容性支持声明：`examples/xray-compatible/README.md` 与实际测试一致，不把 parse-only 标为 fully supported。
- [ ] 治理：`AGENTS.md`、`.github/**`、`vendor/**`、`ref/**`、`LESSONS.md` 或发布相关路径变化经过维护者审批；不可自改保护规则。
- [ ] 未通过的 CI、阻断级 Review、缺少关键环境/凭据都不能伪装为 ready-to-merge。

## 评论格式

每一项发现应包含：
1. `[BLOCKER|HIGH|MEDIUM|LOW]` 标题；
2. 路径及具体行/代码片段；
3. 可复核的触发条件或缺失的验证步骤；
4. 为什么违反 Xray 兼容性、项目架构或安全约束；
5. 建议最小修复方式。

无发现时可以给出“审查范围内未发现阻断问题”，但不能宣称没有 Bug。列出审查覆盖的文件、跳过项以及独立验证命令。

## Reviewer 输出模板

```text
Risk class: L0 / L1 / L2 / L3
Decision: REQUEST_CHANGES / COMMENT / APPROVE_WITH_EVIDENCE
Reviewed paths:
Findings (severity, file:line, reproduction):
Commands actually run + results:
Coverage gaps / environmental blockers:
Compatibility baseline and runtime combinations checked:
Required human approval / release authorization:
```
