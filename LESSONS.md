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
| LESSON-20261026-001 | 2026-10-26 | Release/Workflow | 发布候选没有生成 master 分支保护要求的 Required checks | Mitigated locally; remote verification pending | [Failed release run 40269089545](https://github.com/MFSGA/Chimera_Server/actions/runs/40269089545) |
| LESSON-20261023-001 | 2026-10-23 | Workflow | 自动合并首次预检未重试暂时不完整的 CI job 列表 | Verified | [CI run 39916929938](https://github.com/MFSGA/Chimera_Server/actions/runs/39916929938), [auto-merge run 39917597051, attempts 1–2](https://github.com/MFSGA/Chimera_Server/actions/runs/39917597051), [merged PR #31](https://github.com/MFSGA/Chimera_Server/pull/31), [fix CI run 39919191799](https://github.com/MFSGA/Chimera_Server/actions/runs/39919191799) |
| LESSON-20261017-001 | 2026-10-17 | Test/Workflow | Xray smoke test 依赖被忽略的本地证书 | Verified | [Failed run 39077494361](https://github.com/MFSGA/Chimera_Server/actions/runs/39077494361), [passing rerun 39078597338](https://github.com/MFSGA/Chimera_Server/actions/runs/39078597338) |
| LESSON-20261017-002 | 2026-10-17 | Test/Workflow | Xray smoke 的 loopback echo 目标被 Freedom 私网默认规则拒绝 | Verified | [Local reproduction log](/tmp/chimera-xray-client-vless-tcp-none-149849-1792278770553/chimera.stderr.log), [passing rerun 39078597338](https://github.com/MFSGA/Chimera_Server/actions/runs/39078597338) |
| LESSON-20261016-001 | 2026-10-16 | Workflow | 自动合并范围误设为所有同仓 PR | Mitigated locally; corrective CI pending | [Overbroad policy commit 22fdde9](https://github.com/MFSGA/Chimera_Server/commit/22fdde9a87685fdc057ec9dc15d52cf417b0c2bb) |
| LESSON-20261015-001 | 2026-10-15 | Workflow | 自动合并预检把 Actions jobs 响应误判为列表 | Pushed; remote verification pending | [Auto-merge run 38738346030](https://github.com/MFSGA/Chimera_Server/actions/runs/38738346030) |

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

### LESSON-20261026-001: 发布候选没有生成 master 分支保护要求的 Required checks
- 发现日期（UTC）：2026-10-26
- 分类：Release / Workflow
- 严重度：High
- 状态：Mitigated locally; remote verification pending
- 证据：[失败的 Build and Release run 40269089545](https://github.com/MFSGA/Chimera_Server/actions/runs/40269089545) 中，候选 SHA `81514397e5a85d1f8084c8d16d8dcb597680b885` 的平台预检、功能矩阵、release gates 和制品作业通过；原子更新 `master` 与标签时，GitHub 因 required status check `Required checks` 为 expected 而拒绝推送。该候选 SHA 的检查列表没有 CI run；基线 SHA `38359faa364215b3b67d35f8c59f1137ab53d8b0` 有成功的 `Required checks`。当时的 `ci.yml` 只在 `master` push、面向 `master` 的 PR 和手动 dispatch 时触发。
- 影响范围：稳定发布；候选版本的所有发布作业可通过，但 `master` 与标签的原子推送因严格分支保护失败。
- 观察到的失败：发布 run 的其他验证和构建步骤成功；最终 Git push 失败，且原子操作未留下 `master` 版本更新或稳定标签。
- 根本原因：发布准备 job 用 `GITHUB_TOKEN` 将临时 release candidate 分支推送到远端。由 `GITHUB_TOKEN` 触发的普通 `push` 不会启动新的 Actions workflow，因此候选提交没有 branch protection 所需的 `Required checks` 检查上下文。发布 workflow 自己的其他成功 job 不能替代该受保护检查。
- 修复措施：新增候选 CI 验证脚本；release workflow 用有界等待显式 dispatch 普通 CI 到候选分支，校验 workflow、事件、分支和完整候选 SHA，并要求该次 CI run 的 `Required checks` 汇总 job 唯一且成功后才允许 `Publish`。没有放宽分支保护或跳过 required check。
- 预防措施：CI 加入脚本模拟自测，覆盖迟到 run、同一候选分支上的历史 run、失败 CI、缺失/重复 required job、错误 SHA 和非候选分支；发布流程文档说明显式 dispatch 及严格门禁。
- 回归验证：`python3 .github/scripts/release_candidate_ci.py --self-test`、`python3 -m py_compile .github/scripts/release_candidate_ci.py`、`python3 .github/scripts/release_version.py --self-test`、`python3 .github/scripts/auto_merge_after_ci.py --self-test`、`git diff --check` 均通过。`actionlint` 不在当前环境中，尚未执行；当前尚未重跑真实 release dispatch，因此还没有远端证据证明 GitHub 分支保护已接受候选检查。
- 重复事件：无已知关联事件。
- 是否提议升级为强制规则：否；现有保护规则保持不变，补齐 candidate SHA 的 required CI 即可。

### LESSON-20261023-001: 自动合并预检没有重试暂时不完整的 CI job 列表
- 发现日期（UTC）：2026-10-23
- 分类：Workflow
- 严重度：Medium
- 状态：Verified
- 证据：PR #31 head `58f20524bc6510f2a4f92c90ba7e2bff31110c00` 的 [CI run 39916929938](https://github.com/MFSGA/Chimera_Server/actions/runs/39916929938) 全部 12 个必需 job 均成功。该次完成事件的 [自动合并 run 39917597051 第一次执行](https://github.com/MFSGA/Chimera_Server/actions/runs/39917597051) 报告缺少成功 job；同一预检使用相同 CI run 重跑后，[第二次执行成功并合并 PR #31](https://github.com/MFSGA/Chimera_Server/pull/31)。修复提交 `ee61eb93450de9b680aa5b9b710fa950253f88cd` 的 [CI run 39919191799](https://github.com/MFSGA/Chimera_Server/actions/runs/39919191799) 全部 12 个 job 成功，包含 `Required checks`。
- 影响范围：符合资格的 Dependabot Cargo PR 在 CI 全绿时可能因第一次检查 job 列表不完整而保持打开。
- 观察到的失败：CI 成功后自动合并首次预检报告缺少必需 job 并安全跳过；随后对同一 workflow-run 事件重跑则成功。
- 根本原因：脚本只读取一次 Actions jobs API；当该读取没有显示全部已完成 job 时立即跳过，没有对短暂不完整的列表做有界重试。首次响应内容未被保留，具体缺失字段或 job 不确定；同一 run 后续重读和重跑均成功，支持这是短时可见性问题。
- 修复措施：将必需 job 检查区分为暂未可见/运行中、失败和重复；只对暂未可见或未完成的 job 列表最多重读五次，间隔两秒。失败、重复和重试耗尽仍安全跳过，并报告相关 job 名称。
- 预防措施：策略自检使用模拟 API 覆盖先返回不完整列表、后返回全绿列表的重试路径，以及重试耗尽、真实失败和重复 job 不误合并的情况。
- 回归验证：`python3 .github/scripts/auto_merge_after_ci.py --self-test`（通过，覆盖临时不完整后恢复、重试耗尽、失败和重复 job）、`python3 -m py_compile .github/scripts/auto_merge_after_ci.py`（通过）、`git diff --check`（通过）；推送后的 [CI run 39919191799](https://github.com/MFSGA/Chimera_Server/actions/runs/39919191799) 在 commit `ee61eb93450de9b680aa5b9b710fa950253f88cd` 上 12/12 job 成功。
- 重复事件：LESSON-20261015-001 涉及不同问题（jobs API 分页响应形状），不是同一故障。
- 是否提议升级为强制规则：否；以脚本重试和回归自检覆盖该短时不完整响应。

### LESSON-20261017-001: Xray smoke test 误依赖被忽略的本地证书
- 发现日期（UTC）：2026-10-17
- 分类：CI
- 严重度：Low
- 状态：Verified
- 证据：[失败的 Xray Compatibility Smoke run 39077494361](https://github.com/MFSGA/Chimera_Server/actions/runs/39077494361) 首个测试在 `first_cert_sha256_hex` 打开 `cert/cert.pem` 时失败；修复后的 [Xray Compatibility Smoke run 39078597338](https://github.com/MFSGA/Chimera_Server/actions/runs/39078597338) 全部通过。
- 影响范围：`xray_client_can_proxy_tcp_through_chimera_vless_tcp` 在干净 checkout 中无法启动；该测试的 TCP/none 分支不使用 TLS。
- 观察到的失败：手动 smoke workflow 下载和验证 Xray 成功，运行第一个端到端测试时因 `cert/cert.pem` 不存在而 panic；`cert/` 被 `.gitignore` 忽略。
- 根本原因：公共传输测试 helper 在匹配 TCP/WebSocket/TLS 场景之前无条件打开工作区证书，而非 TLS 场景也执行这一步。开发者本地忽略目录掩盖了 clean-checkout 问题。
- 修复措施：仅在 WebSocket TLS 用例中于临时测试目录生成证书，并据此计算 pin；非 TLS 用例不再访问 `cert/`。
- 预防措施：端到端测试证书由测试自身生成；手动兼容性 workflow 需在干净的 GitHub runner 上运行。
- 回归验证：使用校验和固定的 Xray 26.7.28 客户端，GitHub workflow 中 VLESS TCP、gRPC、HTTPUpgrade 三条精确 ignored 测试均通过；另在本地运行的 `xray_client_can_proxy_tcp_through_chimera_vless_ws` 与 `xray_client_can_proxy_tcp_through_chimera_vless_wss` 用例也通过。workflow：[39078597338](https://github.com/MFSGA/Chimera_Server/actions/runs/39078597338)。
- 重复事件：无已知关联事件。
- 是否提议升级为强制规则：否；问题局限于测试夹具的自包含性。

### LESSON-20261017-002: Xray smoke 的 loopback echo 目标被 Freedom 私网默认规则拒绝
- 发现日期（UTC）：2026-10-17
- 分类：CI
- 严重度：Low
- 状态：Verified
- 证据：Xray 26.7.28 下复现；Chimera 日志 `/tmp/chimera-xray-client-vless-tcp-none-149849-1792278770553/chimera.stderr.log` 显示选中了 `direct` Freedom outbound，随后以 `TCP outbound routing rejected connection` 关闭会话。修复后的 [Xray Compatibility Smoke run 39078597338](https://github.com/MFSGA/Chimera_Server/actions/runs/39078597338) 通过。
- 影响范围：手动 smoke 中 VLESS TCP、gRPC、HTTPUpgrade 三项都通过 loopback TCP echo server 验证数据面。
- 观察到的失败：Xray 成功连入 Chimera，SOCKS 建立成功，但请求 `127.0.0.1:<echo-port>` 被拒绝，客户端读取 echo 时遇到 EOF。
- 根本原因：Chimera 按 Xray VLESS 默认规则拒绝私有 IP；测试夹具没有为本地 echo 目标设置显式 Freedom allow 规则。这不是传输实现故障。
- 修复措施：仅在三个兼容性测试的 Freedom 配置中允许 `127.0.0.1/32`、TCP 和该测试随机分配的 echo 端口；生产策略保持不变。
- 预防措施：端到端测试使用受限的显式策略放行本机 fixture，不能通过放宽生产默认策略来绕开测试环境限制。
- 回归验证：GitHub workflow 中 VLESS TCP、gRPC、HTTPUpgrade 三条精确 ignored 测试全部通过；本地使用同一固定版本 Xray 的这三项及额外 VLESS WebSocket TLS 用例也分别通过。Xray client：26.7.28；`ref/xray-core`：`701af60772cda123492f86e383e1fdba066614a9`。workflow：[39078597338](https://github.com/MFSGA/Chimera_Server/actions/runs/39078597338)。
- 重复事件：无已知关联事件。
- 是否提议升级为强制规则：否；通过显式测试配置即可避免。

### LESSON-20261016-001: 自动合并策略范围误设为所有同仓 PR
- 发现日期（UTC）：2026-10-16
- 分类：Workflow
- 严重度：Medium
- 状态：Mitigated locally; corrective CI pending
- 证据：[过宽策略提交 22fdde9](https://github.com/MFSGA/Chimera_Server/commit/22fdde9a87685fdc057ec9dc15d52cf417b0c2bb)；用户澄清目标仅为 Dependabot 依赖更新；检查时所有 13 个打开 PR 均为 Dependabot，且均无已启用的 Auto-merge 请求。
- 影响范围：自动合并候选资格；若非 Dependabot PR 触发工作流，过宽策略可能为它们请求或完成合并。
- 观察到的失败：实现把“依赖更新自动合并”扩大成“同仓目标为 master 的所有 PR 自动合并”；尚未观察到非 Dependabot PR 被启用或合并。
- 根本原因：将自动合并范围从 PR 的来源/类别误推断为所有满足 CI 和分支规则的 PR。
- 修复措施：仅允许 `dependabot[bot]` 的同仓 `master` Cargo 依赖 PR，变更必须只包含 `Cargo.toml`/`Cargo.lock`，并排除 L3 治理、工作流、发布、参考源码和 vendor 路径；普通 PR 在调用合并 API 前即跳过。只在所有门禁已满足时用固定 head SHA 同步合并，不创建可延迟完成的原生 Auto-merge 请求。
- 预防措施：CI 自测明确验证 Cargo 依赖 PR 可合并、普通 PR/非 Cargo 文件/L3 路径不可合并、base 或文件清单复查变化时跳过、门禁未满足时不调用合并 API；工作流文档同步明确范围。
- 回归验证：`python3 .github/scripts/auto_merge_after_ci.py --self-test`、`python3 -m py_compile .github/scripts/auto_merge_after_ci.py`、`git diff --check`；纠正提交推送后的 CI 待验证。
- 重复事件：LESSON-20261015-001 是不同问题（GitHub jobs 响应解析）。
- 是否提议升级为强制规则：否；针对该范围的候选资格自测已加入 CI。

### LESSON-20261015-001: 自动合并预检误读 GitHub Actions jobs 响应
- 发现日期（UTC）：2026-10-15
- 分类：Workflow
- 严重度：Medium
- 状态：Mitigated（修复已推送；远端验证待完成）
- 证据：[失败的 Auto-merge run 38738346030](https://github.com/MFSGA/Chimera_Server/actions/runs/38738346030)；关联 CI run 38737272211 成功，GitHub jobs 接口返回 12 个 job。
- 影响范围：`auto-merge.yml` 的 `workflow_run` 预检路径；符合现有分支保护规则的 PR（包括 Dependabot 更新）在 CI 成功后无法进入自动合并预检。
- 观察到的失败：预期从成功 CI run 读取全部 job；实际报 `GitHub API returned an unexpected list response` 并安全退出。
- 根本原因：脚本将 `GET /actions/runs/{run_id}/jobs` 当成裸数组解析；GitHub 实际返回 `{ "total_count": ..., "jobs": [...] }` 分页对象。issue events 和 PR files 接口仍返回裸数组，不能统一假定所有列表端点具有相同外层结构。
- 修复措施：`get_all` 可按显式 `collection_key` 读取包装列表，CI jobs 使用 `jobs` 键；原有裸数组读取保持不变。
- 预防措施：CI 中的 auto-merge policy self-test 覆盖包装分页、`Link` 翻页、现有裸数组和缺失 `jobs` 字段时 fail closed。
- 回归验证：`python3 .github/scripts/auto_merge_after_ci.py --self-test`、`python3 -m py_compile .github/scripts/auto_merge_after_ci.py`、`git diff --check` 均通过；修复后远端 Actions 验证尚未执行。
- 重复事件：无已知关联事件。
- 是否提议升级为强制规则：否；现有 CI 自测足以覆盖这一具体 API 响应契约。
