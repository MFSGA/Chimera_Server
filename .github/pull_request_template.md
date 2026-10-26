## 目标与验收条件
<!-- 说明 Issue、可观察行为、非目标；避免在一个 PR 混合多个协议目标。 -->

## 改动范围与架构所有权
<!-- 哪些模块、状态 owner、配置→运行链路？是否更新了 ARCHITECTURE / ITERATION_GUIDE？ -->

## 风险等级
- [ ] L0：仅非行为性文档
- [ ] L1：低风险局部改动
- [ ] L2：协议/安全/运行时/feature/平台/依赖
- [ ] L3：工程规则、CI/发布、凭据、ref/vendor 或生产部署

风险原因：

## Xray 兼容性
<!-- 如适用，填写固定 ref/xray-core commit/tag、真实客户端版本、协议×传输×安全×TCP/UDP 组合及差异。 -->
<!-- 如有支持范围变化，更新 examples/xray-compatible/README.md。 -->

## 实际验证证据
| 命令/检查 | 环境/版本 | 结果（通过/失败/未执行） | 证据链接或原因 |
| --- | --- | --- | --- |
| `cargo fmt --all -- --check` | | | |
| Clippy / 相关 Rust 测试 | | | |
| 兼容互通 / feature / Windows（按变更范围） | | | |
| CI / 其他检查 | | | |

## 独立审查与遗留风险
<!-- 参考 docs/ai-review-checklist.md；说明 Reviewer、阻断项及解决情况，未验证项不得隐藏。 -->

## 回滚与发布
<!-- 本 PR 是否需要回滚步骤？提交 PR 不意味着授权发布；稳定版仍使用 manual release workflow。 -->

## 交付确认
- [ ] 已读取 `AGENTS.md` 及相关设计、历史 Lesson
- [ ] 修改范围最小，未引入无关变更
- [ ] 明确列出未执行的检查，不伪造通过结果
- 自动合并范围：仅 `dependabot[bot]` 的同仓 `master` Cargo 依赖 PR（只改 `Cargo.toml`/`Cargo.lock`）和 GitHub Actions 固定 SHA 引用 PR（只替换同一 action 的 SHA）；必须满足所有 required CI 和其他 GitHub 合并条件。其他 PR 和 L3 改动仍由人工合并；`master` 保留必需 CI 检查，但不由 GitHub 强制要求审批人数，仓库审查流程仍适用。
