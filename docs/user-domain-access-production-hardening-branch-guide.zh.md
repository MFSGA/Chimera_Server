# `feat/user-domain-access-production-hardening` 分支说明

## 1. 文档目的

本文说明当前分支 `feat/user-domain-access-production-hardening` 的设计目标、实际作用、关键能力、配置方法、运行流程、典型使用场景、故障处理方式和上线建议。

该分支不是重新实现一套代理协议，也不是改变 Chimera Server 的基础转发模型。它建立在已经完成的“用户身份 + 目标域名访问控制”能力之上，重点解决一个更接近生产环境的问题：

> 当策略控制已经能够工作以后，怎样确保它可以安全发布、平滑灰度、稳定持久化、快速回滚、有效观测，并且不会因为错误策略、错误签名、磁盘异常或超大配置而影响整个节点。

因此，这个分支的核心作用可以概括为：

> 将用户域名访问控制从“功能可用”提升为“具备生产部署条件”。

---

## 2. 分支定位

当前分支基于 `feat/user-domain-access-control` 继续开发。

基础分支已经完成以下能力：

- 根据认证用户识别稳定的 backend 用户 UUID；
- 根据目标域名、TLS SNI、HTTP Host 或 IP 地址进行目标分类；
- 支持 `exact` 和 `suffix` 域名匹配；
- 支持 `allowlist`、`denylist` 和 `allow_all` 用户策略；
- 在 DNS 解析和出站连接建立之前作出允许或拒绝决定；
- 支持动态 Apply、Status、Rollback；
- 支持版本递增、checksum、防重放、持久化和历史版本回滚。

当前生产加固分支进一步增加：

1. `enforce`、`shadow`、`disabled` 三种执行模式；
2. 固定低基数生产指标；
3. Ed25519 策略签名验证；
4. 策略持久化文件安全保护；
5. 用户数和规则数资源上限；
6. 可配置且有界的 TLS ClientHello 探测；
7. Criterion 性能基准；
8. 更完整的上线、灰度、密钥轮换和故障演练说明。

换句话说，基础分支回答的是“能否按用户和域名控制访问”，当前分支回答的是“能否放心地在真实节点上启用这项控制”。

---

## 3. 它解决了什么实际问题

### 3.1 防止策略直接上线造成大面积误封

没有灰度模式时，新策略一旦发布就可能立即阻断业务。例如，backend 忘记为某个用户加入 `api.example.com`，节点进入强制模式后，该用户的连接会立刻失败。

当前分支加入 `shadow` 模式。系统仍然完整执行身份识别、域名分类和规则匹配，也会统计“本来应该拒绝”的连接，但实际数据面继续放行。

这样可以在真实流量中提前发现规则遗漏，而不影响用户。

### 3.2 防止策略包在传输途中被篡改

checksum 能发现内容是否发生变化，但如果攻击者可以同时替换配置和 checksum，仅靠 checksum 不能证明发布者身份。

当前分支加入 Ed25519 签名验证。节点本地保存可信公钥，backend 使用对应私钥对策略包签名。节点在写盘和替换运行时策略之前完成验签。

这意味着：

- checksum 错误会被拒绝；
- 签名错误会被拒绝；
- 未知 key ID 会被拒绝；
- 配置要求签名但策略没有签名时会被拒绝；
- 被拒绝的策略不会覆盖当前有效策略。

### 3.3 防止持久化文件成为安全或稳定性风险

策略文件可能包含用户 UUID、协议身份映射和域名规则。如果权限过宽，其他本地用户可能读取这些信息；如果路径被替换为符号链接，节点可能覆盖非预期文件；如果文件异常巨大，启动时可能消耗过多内存。

当前分支对此增加以下保护：

- 存储文件最大 16 MiB；
- 读取和覆盖时拒绝符号链接；
- 拒绝非普通文件；
- Unix 临时文件使用 `0600` 权限；
- 写入临时文件后执行 flush 和 fsync；
- 使用原子 rename 替换正式文件；
- 目录执行 fsync；
- 任一步骤失败时保留当前内存策略和旧存储文件。

### 3.4 防止恶意或错误大配置拖垮节点

一个包含数百万用户或数千万规则的动态策略，即使语法正确，也可能造成内存暴涨和长时间编译。

当前分支在创建大容量 HashMap 和规则向量之前进行限制：

- 最多 100,000 个用户；
- 每个用户最多 10,000 条规则；
- 全局最多 1,000,000 条规则。

这些是代码级硬上限，不依赖 backend 是否正确。

### 3.5 控制 TLS 域名探测对首包延迟的影响

当协议目标只有 IP 地址时，系统可以短暂读取 TLS ClientHello，尝试提取 SNI。探测过短会降低 SNI 识别率，探测过长则可能增加首包延迟。

当前分支将原先固定的探测参数变为节点本地配置：

- 默认超时：5ms；
- 默认捕获上限：64KiB；
- 超时允许范围：1–100ms；
- 捕获上限允许范围：1–256KiB。

读取严格不会越过配置的最大字节数，并且所有已读取和未读取字节都会按原顺序交还给后续协议处理，不会吞掉 ClientHello 或应用数据。

---

## 4. 整体工作流程

生产环境中的典型调用链如下：

```text
中央 backend
    │
    │ 生成版本化策略、checksum、Ed25519 signature
    ▼
Rust rnode 或 Nest 节点服务
    │
    │ HTTPS + JWT / 可选 mTLS
    ▼
Chimera gRPC UserDomainAccessService
    │
    ├─ 校验 JSON 结构
    ├─ 校验版本和 targetNodeUuid
    ├─ 校验 checksum
    ├─ 校验 Ed25519 signature
    ├─ 校验用户/规则规模上限
    ├─ 编译策略
    ├─ 原子持久化
    └─ 原子替换 RuntimeState
             │
             ▼
认证连接进入数据面
    │
    ├─ 协议身份映射为 backend 用户 UUID
    ├─ 获取目标域名 / SNI / Host / IP
    ├─ 根据用户策略匹配 exact 或 suffix 规则
    ├─ 记录固定维度指标
    └─ enforce 阻断，shadow 放行，disabled 绕过
```

策略决策发生在 DNS 解析和出站连接建立之前，因此被拒绝的目标不会先建立外部连接。

---

## 5. 三种执行模式

### 5.1 `enforce`

`enforce` 是默认模式，也是正式强制访问控制模式。

当策略返回 `reject` 时，连接在出站建立之前被拒绝。

适用场景：

- 规则已经通过 shadow 验证；
- 指标和告警已经接入；
- 已完成回滚演练；
- 可以接受策略拒绝直接影响业务。

示例：

```json
{
  "enforcementMode": "enforce",
  "defaultAction": "reject",
  "users": []
}
```

如果用户策略只允许 `api.example.com`，访问 `video.example.com` 会被真正阻断，并增加 `enforcedRejections`。

### 5.2 `shadow`

`shadow` 会执行完整策略决策，但不会真正阻断。

示例：

```json
{
  "enforcementMode": "shadow",
  "defaultAction": "reject",
  "users": []
}
```

假设某连接按策略应被拒绝：

- 原始决策仍为 `reject`；
- `rejected` 增加；
- `shadowRejections` 增加；
- `enforcedRejections` 不增加；
- 实际连接继续建立。

它最适合首次上线和规则变更前验证。

### 5.3 `disabled`

`disabled` 用于完全关闭策略执行，但保留策略发布链和身份映射配置。

在该模式下，系统不会进行：

- 目标域名分类；
- TLS ClientHello 探测；
- exact/suffix 匹配；
- allow/reject 决策。

它会增加 `disabledBypasses`，但不会增加策略 evaluations。

适用场景：

- 首次验证 backend → rnode → gRPC → 节点的发布链；
- 紧急停止访问控制；
- 排查策略系统是否影响首包延迟；
- 保留配置但暂时绕过数据面执行。

---

## 6. 完整配置示例

下面示例展示一个开启 gRPC、持久化、签名验证和 shadow 模式的节点配置。

```json
{
  "api": {
    "listen": "127.0.0.1:8080",
    "services": ["UserDomainAccessService"]
  },
  "userDomainAccessStore": {
    "path": "state/user-domain-access.json",
    "nodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "requireSignature": true,
    "tlsProbeTimeoutMillis": 5,
    "tlsProbeMaxBytes": 65536,
    "trustedSigningKeys": [
      {
        "keyId": "backend-key-2026-01",
        "publicKey": "<base64-encoded-32-byte-ed25519-public-key>"
      },
      {
        "keyId": "backend-key-2026-02",
        "publicKey": "<new-base64-public-key-for-key-rotation>"
      }
    ]
  },
  "userDomainAccess": {
    "version": 12,
    "generatedAt": "2026-08-04T12:00:00Z",
    "sourceBackendVersion": "backend-2026.08.04",
    "targetNodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "signatureAlgorithm": "ed25519",
    "signingKeyId": "backend-key-2026-02",
    "checksum": "sha256:<canonical-json-sha256>",
    "signature": "<base64-ed25519-signature>",
    "enforcementMode": "shadow",
    "defaultAction": "reject",
    "users": [
      {
        "userUuid": "11111111-1111-4111-8111-111111111111",
        "protocolIdentity": {
          "vlessUuid": "22222222-2222-4222-8222-222222222222",
          "httpUsername": "alice",
          "socksUsername": "alice"
        },
        "mode": "allowlist",
        "unknownTargetAction": "reject",
        "rules": [
          {
            "id": "allow-api",
            "domain": "api.example.com",
            "match": "exact",
            "action": "allow",
            "priority": 10
          },
          {
            "id": "allow-corp-subdomains",
            "domain": "corp.example.com",
            "match": "suffix",
            "action": "allow",
            "priority": 20
          }
        ]
      },
      {
        "userUuid": "33333333-3333-4333-8333-333333333333",
        "mode": "denylist",
        "unknownTargetAction": "allow",
        "rules": [
          {
            "id": "block-video",
            "domain": "video.example.net",
            "match": "suffix",
            "action": "reject",
            "priority": 10
          }
        ]
      }
    ]
  }
}
```

### 6.1 示例决策结果

| 用户 | 目标 | 规则结果 | shadow 下实际行为 | enforce 下实际行为 |
|---|---|---|---|---|
| Alice | `api.example.com` | exact allow | 放行 | 放行 |
| Alice | `service.corp.example.com` | suffix allow | 放行 | 放行 |
| Alice | `corp.example.com.evil.org` | 不匹配 | 放行并记录 shadow reject | 拒绝 |
| Alice | 直接访问 `192.0.2.10`，无可信 SNI | unknownTargetAction=reject | 放行并记录 shadow reject | 拒绝 |
| 第二个用户 | `cdn.video.example.net` | suffix reject | 放行并记录 shadow reject | 拒绝 |
| 第二个用户 | `docs.example.org` | denylist miss，默认允许 | 放行 | 放行 |

`suffix` 匹配遵守 DNS label 边界。例如规则 `example.com` 可以匹配 `api.example.com`，但不会匹配 `notexample.com` 或 `example.com.evil.org`。

---

## 7. checksum 与签名的作用

### 7.1 checksum

checksum 使用 canonical JSON SHA-256。

计算时排除顶层：

- `checksum`；
- `signature`。

然后对对象 key 排序并计算 SHA-256，结果格式为：

```text
sha256:<64位十六进制字符串>
```

checksum 的主要作用是发现内容变化和跨语言实现不一致。

### 7.2 Ed25519 签名

签名 payload 只排除顶层 `signature`，因此签名覆盖：

- checksum；
- version；
- targetNodeUuid；
- signingKeyId；
- signatureAlgorithm；
- enforcementMode；
- 用户和规则内容；
- 其他发布元数据。

这可以同时证明“内容未被修改”和“发布包由受信私钥持有者生成”。

### 7.3 错误签名示例

假设当前节点只信任 `backend-key-2026-02`，但收到：

```json
{
  "signingKeyId": "unknown-key",
  "signatureAlgorithm": "ed25519",
  "signature": "..."
}
```

Apply 会返回权限错误，节点将：

- 不写入存储文件；
- 不替换当前 RuntimeState；
- 增加 Apply 失败指标；
- 继续使用旧版本策略。

### 7.4 密钥轮换示例

推荐顺序：

1. 节点同时配置旧公钥和新公钥；
2. backend 继续使用旧 key 发布一次，确认兼容；
3. backend 改用新 key 发布；
4. Status 确认当前 `signingKeyId` 为新 key；
5. 执行一次重启恢复和回滚演练；
6. 从节点移除旧公钥。

不要先删除旧公钥再切换 backend，否则仍使用旧 key 签名的策略和历史版本可能无法通过启动校验。

---

## 8. 版本、防重放和回滚

动态 Apply 要求新版本严格高于节点运行期见过的最高版本。

例如：

```text
当前版本：12
highestSeenVersion：15
```

这可能表示节点曾运行版本 15，后来回滚到了 12。

此时：

- Apply 版本 13：拒绝；
- Apply 版本 15：拒绝；
- Apply 版本 16：允许；
- Rollback 到保留历史中的 14：允许；
- 回滚后 highestSeenVersion 仍保持 16。

这样可以防止攻击者在回滚后重新发送旧的高版本策略包。

节点最多保留 5 个历史版本，用于快速回滚。

---

## 9. CLI 操作示例

### 9.1 发布策略

```bash
chimera-cli user-domain-access \
  --endpoint http://127.0.0.1:8080 \
  apply ./policy-v16.json
```

成功后返回当前 revision 信息，例如：

```json
{
  "revision": {
    "version": 16,
    "generatedAt": "2026-08-04T12:30:00Z",
    "sourceBackendVersion": "backend-2026.08.04",
    "targetNodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "checksum": "sha256:...",
    "signatureAlgorithm": "ed25519",
    "signingKeyId": "backend-key-2026-02"
  }
}
```

### 9.2 查看状态

```bash
chimera-cli user-domain-access \
  --endpoint 127.0.0.1:8080 \
  status
```

典型输出结构：

```json
{
  "revision": {
    "version": 16,
    "checksum": "sha256:...",
    "signingKeyId": "backend-key-2026-02"
  },
  "stats": {
    "evaluations": 100000,
    "allowed": 98000,
    "rejected": 2000,
    "enforcedRejections": 0,
    "shadowRejections": 2000,
    "disabledBypasses": 0,
    "unknownTarget": 450,
    "tlsProbeAttempts": 1200,
    "tlsSniFound": 900,
    "tlsEchDetected": 40,
    "tlsTimeouts": 25,
    "applySucceeded": 4,
    "applyFailed": 1,
    "rollbackSucceeded": 1,
    "rollbackFailed": 0
  },
  "tlsProbeTimeoutMillis": 5,
  "tlsProbeMaxBytes": 65536
}
```

这组数据说明：策略正在 shadow 运行，已有 2,000 次“本来会拒绝”的连接，但没有真正阻断。

### 9.3 回滚策略

```bash
chimera-cli user-domain-access \
  --endpoint 127.0.0.1:8080 \
  rollback 15
```

回滚只允许选择仍在最近历史中的版本。如果版本不存在，会返回失败并增加 rollback failure 指标。

---

## 10. TLS ClientHello 探测示例

### 10.1 为什么需要探测

某些协议只提供目标 IP：

```text
192.0.2.10:443
```

仅根据 IP 无法匹配域名规则。系统会在有界时间内读取 TLS ClientHello，尝试提取：

```text
SNI = api.example.com
```

若成功，就可以按 `api.example.com` 执行域名策略。

### 10.2 ECH 行为

当 ClientHello 使用 ECH 时，外层 SNI 不被视为可信业务域名。系统将目标按 unknown/IP 处理，并执行用户的 `unknownTargetAction`。

例如用户配置：

```json
{
  "unknownTargetAction": "reject"
}
```

则在 enforce 模式下，无法获得可信域名的 ECH 连接会被拒绝；在 shadow 模式下只记录 would-reject。

### 10.3 参数调整建议

可测试以下矩阵：

```text
超时：1 / 5 / 10 / 25 ms
最大捕获：16 / 64 / 128 / 256 KiB
```

观察：

- 首包延迟 p50/p95/p99；
- SNI 识别成功率；
- timeout 比例；
- incomplete/malformed 比例；
- shadow unknown target 比例。

不要简单地将超时设置为 100ms。更长时间可能提高极少量分片 ClientHello 的识别率，却给所有相关连接增加等待上限。

---

## 11. 可观测性设计

当前分支刻意使用固定低基数指标，不把以下内容作为标签：

- 用户 UUID；
- 域名；
- IP 地址；
- 连接 ID；
- 规则 ID。

这样可以避免指标系统因为用户数和域名数增长而出现高基数问题。

主要指标分类如下。

### 11.1 决策结果

- `evaluations`：实际执行策略的次数；
- `allowed`：原始允许决策；
- `rejected`：原始拒绝决策；
- `enforcedRejections`：真正阻断的次数；
- `shadowRejections`：shadow 中本来会拒绝的次数；
- `disabledBypasses`：disabled 绕过次数。

### 11.2 决策原因

- `matchedRule`；
- `noUserPolicy`；
- `unknownTarget`；
- `allowAllDefault`；
- `allowlistMiss`；
- `denylistMiss`。

### 11.3 TLS 探测

- `tlsProbeAttempts`；
- `tlsSniFound`；
- `tlsEchDetected`；
- `tlsNotTls`；
- `tlsIncomplete`；
- `tlsMalformed`；
- `tlsNoServerName`；
- `tlsTimeouts`；
- `tlsCapturedBytes`。

### 11.4 控制面操作

- `applySucceeded`；
- `applyFailed`；
- `rollbackSucceeded`；
- `rollbackFailed`。

建议至少为以下情况设置告警：

- Apply 连续失败；
- shadow reject 比例突然升高；
- unknown target 比例异常；
- TLS timeout 比例异常；
- enforce reject 比例超过业务预期；
- 节点 Status checksum 与 backend 发布记录不一致。

---

## 12. 故障场景与系统行为

### 12.1 错误目标节点

策略中的：

```json
{
  "targetNodeUuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
}
```

与本机配置的 node UUID 不一致。

结果：Apply 被拒绝，旧策略继续运行。

### 12.2 版本重放

节点最高见过版本为 20，攻击者重新发送版本 18。

结果：Apply 被拒绝，即使当前节点因为回滚正在运行版本 17。

### 12.3 checksum 或签名错误

结果：在持久化和 RuntimeState 替换前拒绝，旧策略不变。

### 12.4 磁盘满或只读文件系统

策略已经完成校验和编译，但临时文件无法写入或 fsync 失败。

结果：Apply 失败，内存中的当前策略不变，旧正式文件不被覆盖。

### 12.5 存储路径是符号链接

结果：读取或覆盖均被拒绝，避免策略路径指向其他敏感文件。

### 12.6 策略文件超过 16 MiB

结果：在完整 JSON 解析前拒绝，避免异常大文件造成无界内存占用。

### 12.7 用户或规则超过上限

例如用户数量为 100,001。

结果：在大容量 HashMap 分配前拒绝编译，不替换当前策略。

---

## 13. 性能基准

运行命令：

```bash
cargo bench -p chimera_server_lib --bench user_domain_access
```

基准覆盖：

- 1、100、10,000 用户的策略编译；
- 用户查找和末用户决策；
- 1、10、100、1,000 条 exact 规则；
- 1、10、100、1,000 条 suffix 规则；
- 首条规则命中；
- 末条规则命中；
- 无规则命中；
- release profile 下的吞吐和单次耗时。

短时 benchmark smoke 只用于确认基准能运行，不能直接作为生产阈值。

正式性能门禁应记录：

- Git commit；
- Rust 版本；
- release 编译参数；
- CPU 型号和频率策略；
- 内核版本；
- 用户数和规则数；
- Criterion 原始输出；
- 多次独立运行结果。

---

## 14. 推荐上线流程

### 阶段一：发布链验证

使用：

```json
{
  "enforcementMode": "disabled"
}
```

验证：

- backend 能生成版本；
- rnode 能调用 gRPC；
- checksum 一致；
- 签名验证正常；
- Status 版本一致；
- 持久化和重启恢复正常；
- Rollback 正常。

### 阶段二：真实流量观察

切换：

```json
{
  "enforcementMode": "shadow"
}
```

至少观察一个完整业务周期，重点检查：

- shadow reject 数量；
- allowlist miss；
- no user policy；
- unknown target；
- ECH 和 TLS timeout；
- 未映射协议身份；
- 首包延迟变化。

### 阶段三：小比例强制

选少量节点或少量用户进入 `enforce`。

建议扩展顺序：

```text
5% → 25% → 50% → 100%
```

每一阶段都应验证：

- Apply 成功；
- Status checksum 对账；
- 拒绝率符合预期；
- 重启恢复；
- 回滚可用。

### 阶段四：启用强制签名

在所有当前策略和历史存储策略都已签名后，设置：

```json
{
  "requireSignature": true
}
```

如果旧存储策略没有签名，直接启用强制签名可能导致启动按 fail-closed 原则失败。

---

## 15. 当前分支不负责什么

该分支主要完成 Chimera Server 侧生产加固，不代表生产部署已经自动完成。

仍需要在实际环境完成：

- 数据库 migration；
- backend 私钥的离线保护；
- 节点公钥分发；
- JWT 或 mTLS 凭据配置；
- dashboard 和告警；
- 真实业务周期 shadow 观测；
- 密钥轮换演练；
- 磁盘满、断网、只读文件系统故障演练；
- TLS probe 参数矩阵；
- 固定硬件上的性能阈值；
- 多节点分批灰度和回滚流程。

它也不会替代 backend 的业务授权模型。backend 仍然负责决定“哪个用户应该拥有哪些规则”，Chimera Server 负责可靠地执行已发布的策略。

---

## 16. 提交与能力对应关系

| 提交 | 作用 |
|---|---|
| `528d714` | 增加 enforce、shadow、disabled 执行模式 |
| `2b6502f` | 增加生产级固定维度指标和 Status 输出 |
| `c45879a` | 增加 Ed25519 策略发布签名验证 |
| `43366d5` | 增加用户和规则规模 Criterion 基准 |
| `0987523` | 增加生产灰度、签名和基准说明 |
| `aeea214` | 强化策略持久化文件安全 |
| `3b53e66` | 增加用户数和规则数资源上限 |
| `cf7c1de` | 将 TLS ClientHello 探测变为可配置且有界 |
| `99ec150` | 补充持久化和探测加固文档 |

---

## 17. 当前质量状态

该分支当前已通过：

- 776 个 Chimera Server library 测试；
- workspace 集成测试；
- doctest；
- `cargo fmt`；
- 全 workspace、全 feature、全 target Clippy；
- Criterion release benchmark 编译；
- 无默认 feature 构建；
- 仅 `user_domain_access` feature 构建；
- Git diff 边界检查。

测试结果说明代码级功能和兼容性已经闭环，但不能替代真实节点的容量、网络、磁盘和业务流量验收。

---

## 18. 合并前检查清单

合并到主开发分支前建议确认：

- [ ] backend canonical JSON 与 Rust fixture 一致；
- [ ] backend 已支持 Ed25519 签名字段；
- [ ] rnode/Nest 转发时不修改策略 JSON；
- [ ] 节点公钥和 node UUID 配置正确；
- [ ] 旧持久化策略兼容方案已确认；
- [ ] shadow 指标字段已被监控系统采集；
- [ ] TLS probe 默认值符合当前业务；
- [ ] 已准备一键 Rollback 操作；
- [ ] 已完成至少一次重启恢复验证；
- [ ] 已完成错误签名、错误节点、旧版本重放测试；
- [ ] 已完成磁盘写入失败测试；
- [ ] 已完成小比例 enforce 灰度计划。

---

## 19. 总结

`feat/user-domain-access-production-hardening` 的价值不在于增加更多域名匹配语法，而在于为现有访问控制能力补齐生产环境必须具备的安全性、可观测性、灰度能力、持久化可靠性和性能验证手段。

它使系统能够做到：

- 新策略先观察、后强制；
- 策略发布者身份可验证；
- 错误策略不会覆盖当前有效策略；
- 回滚后旧版本不能重放；
- 磁盘和文件异常不会静默破坏状态；
- 超大策略不会无界消耗节点资源；
- TLS 域名探测的延迟和内存成本可以控制；
- 运维人员可以通过 Status 和 CLI 判断节点真实状态；
- 性能变化可以通过标准基准持续回归。

因此，这个分支可以被视为“用户域名访问控制进入生产部署前的最后一层服务端加固”。
