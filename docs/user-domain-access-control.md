# 用户与目标域名访问控制

## 1. 目标

为每个代理用户提供独立的目标域名访问策略，并由 backend 生成策略、下发到 rnode，再由 Chimera Server 在连接建立或转发阶段执行。

典型需求：

- 用户 `autumn` 只允许访问 `example.com` 和 `api.example.com`。
- 用户 `信徒` 允许访问一组域名，其余目标全部拒绝。
- 未配置策略的用户沿用默认行为。
- 策略更新后可以由 backend 推送到指定 rnode，而不是手工修改节点文件。

本能力是“用户身份 + 目标域名”的联合匹配，不是只按域名全局放行。

## 2. 适用范围与限制

### 2.1 可以可靠识别的目标

- VLESS、VMess、Trojan、HTTP、SOCKS、TUIC、Hysteria2 协议中的原始目标地址。
- 目标为 IP 或未知时，在 5 ms 有界窗口内可读取的 TLS ClientHello SNI；已读字节会完整回放。
- HTTP 明文请求中的 Host。
- VLESS/VMess XUDP、Trojan 多目标 UDP、SOCKS UDP、TUIC/Hysteria2 UDP 帧中的原始域名。

### 2.2 不能保证识别的目标

- 直接使用 IP 地址且没有后续可读 TLS ClientHello 的流量。
- TLS ECH 隐藏的真实 SNI；检测到 ECH 时 outer SNI 不作为放行依据。
- 未经过服务端处理的旁路 DNS 或 DoH/DoT。
- QUIC/UDP 帧中没有域名元数据的流量。

因此策略必须明确“域名匹配失败时”的行为。高安全模式应默认拒绝，而不是把未知目标当成允许。

## 3. 核心数据模型

建议在 Chimera Server 中增加用户域名策略，不直接复用节点级全局路由配置。

```json
{
  "userDomainAccess": {
    "version": 12,
    "generatedAt": "2026-08-04T00:00:00Z",
    "sourceBackendVersion": "backend-2026.08.04",
    "targetNodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "checksum": "sha256:<canonical-json-checksum>",
    "defaultAction": "allow",
    "users": [
      {
        "userUuid": "11111111-1111-4111-8111-111111111111",
        "protocolIdentity": {
          "vlessUuid": "22222222-2222-4222-8222-222222222222",
          "httpUsername": "autumn"
        },
        "mode": "allowlist",
        "unknownTargetAction": "reject",
        "rules": [
          {
            "domain": "example.com",
            "match": "suffix",
            "action": "allow"
          },
          {
            "domain": "api.example.com",
            "match": "exact",
            "action": "allow"
          }
        ]
      }
    ]
  }
}
```

### 3.1 用户标识

优先使用稳定的 backend 用户 UUID；协议层的 email、short UUID 或入站 client ID 只作为映射字段。

```json
{
  "userUuid": "<backend-user-uuid>",
  "protocolIdentity": {
    "vlessUuid": "<vless-uuid>",
    "vmessUuid": "<vmess-uuid>",
    "tuicUuid": "<tuic-uuid>",
    "hysteria2Password": "<hysteria2-password>",
    "trojanPassword": "<trojan-password>",
    "httpUsername": "<http-username>",
    "socksUsername": "<socks-username>"
  }
}
```

不要用用户名作为唯一内部键。用户名可以修改，UUID 不应因改名而变化。

### 3.2 匹配类型

当前实现支持：

- `exact`: 只匹配完整域名，例如 `api.example.com`。
- `suffix`: 匹配域名本身及其子域名，例如 `example.com` 匹配 `example.com` 和 `a.example.com`，但不匹配 `badexample.com`。

当前不接受 `keyword`、`regex` 或脚本表达式，以保持确定性和受控的匹配成本。

域名比较应统一转换为小写、去除末尾点号，并使用 DNS label 边界比较，禁止简单的字符串 `ends_with`。

## 4. 规则语义

### 4.1 决策顺序

连接处理顺序建议为：

1. 解析入站用户身份。
2. 提取目标地址、端口、SNI 或 Host。
3. 规范化域名。
4. 查找用户专属策略。
5. 按规则优先级匹配。
6. 执行 `allow`、`reject` 或指定出站动作。
7. 记录命中规则和拒绝原因。

### 4.2 默认行为

建议提供三种策略模式：

- `allow_all`: 用户未配置专属限制时全部允许。
- `allowlist`: 仅允许命中的域名。
- `denylist`: 命中的域名拒绝，其余允许。

对于 `allowlist`，目标无法识别时默认 `reject`。对于兼容旧配置的用户，可以显式设置 `unknownTargetAction: allow`，但必须在日志中标记为不可验证。

### 4.3 规则优先级

采用确定性的优先级：

1. 用户级规则优先于全局规则。
2. `exact` 优先于 `suffix`。
3. 更长的域名后缀优先于更短的后缀。
4. 同级规则按配置中的 `priority` 数字排序，数字越小越优先。
5. 没有命中时使用该用户的 `unknownTargetAction`，再回退到全局默认行为。

## 5. Xray 语义对照

Xray 通常通过入站用户标识和 routing rule 组合完成：

```json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "user": ["autumn"],
        "domain": ["domain:example.com"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "user": ["autumn"],
        "outboundTag": "block"
      }
    ]
  }
}
```

Chimera 不应只复制字符串格式，而应复制以下语义：用户过滤、域名类型、规则顺序、默认出站和阻断动作。backend 的用户 UUID 到协议身份的映射必须在生成配置时完成。

## 6. Chimera Server 改造点

### 6.1 配置解析

- 增加 `user_domain_access` 配置结构。
- 对用户 UUID、域名、动作和匹配类型做严格校验。
- 拒绝重复规则、非法域名、空的 allowlist 和未知动作。
- 配置加载失败时保留旧配置，不切换到空策略。

### 6.2 身份上下文

在 inbound handler 的连接上下文中保存：

```text
user_uuid
protocol_identity
protocol
target_host
target_port
sni
tls_ech
http_host
transport
```

用户身份必须在路由决策之前确定。若身份无法确定，不能错误地套用某个用户的 allowlist。

### 6.3 域名提取器

按以下顺序获取候选目标：

1. 协议层原始目标地址。
2. TLS SNI。
3. HTTP Host。
4. DNS 查询中的 QNAME。

提取器应返回 `ExactDomain`、`IpAddress` 或 `Unknown`，不要把 IP 伪装成域名。

### 6.4 决策引擎

当前使用预编译结构：

- exact 域名使用 `HashMap`。
- suffix 规则按域名 label 数量、priority 和配置顺序预排序。
- 每个用户独立编译规则，连接决策不扫描其他用户。

决策结果至少包含：

```text
allow | reject
matched_rule_id
matched_user_uuid
reason
target_class
```

### 6.5 阻断方式

阻断应在建立出站连接前执行，并返回统一错误。不要先连接目标再关闭，否则会造成资源浪费和策略泄漏。

## 7. backend 与 rnode 下发流程

建议流程：

1. backend 保存用户域名策略。
2. backend 校验用户属于允许下发的分组。
3. backend 根据用户协议凭据生成 rnode 可识别的用户映射。
4. backend 生成带版本号的节点配置。
5. 通过现有 rnode 控制 API 下发配置。
6. rnode 写入临时文件并校验。
7. Chimera Server 原子替换运行配置。
8. rnode 返回配置版本和生效状态。
9. backend 记录审计事件。

配置必须带：

```text
version
generatedAt
sourceBackendVersion
targetNodeUuid
checksum
```

下发失败时不得覆盖当前有效配置。生产环境建议保留最近 2 至 5 个版本，支持回滚。

## 8. API 建议

### 查询用户策略

```http
GET /api/users/{userUuid}/domain-access
```

### 创建或替换用户策略

```http
PUT /api/users/{userUuid}/domain-access
Content-Type: application/json
```

请求体：

```json
{
  "mode": "allowlist",
  "unknownTargetAction": "reject",
  "rules": [
    { "domain": "example.com", "match": "suffix", "action": "allow", "priority": 100 }
  ]
}
```

### 下发到节点

```http
POST /api/nodes/{nodeUuid}/domain-access/publish
```

返回体应包含：

```json
{
  "configVersion": 12,
  "status": "APPLIED",
  "checksum": "...",
  "appliedAt": "..."
}
```

## 9. 安全与运维要求

- backend 到 rnode 的控制 API 继续使用 mTLS/JWT，不因增加该功能而开放明文控制接口。
- 所有策略变更记录操作者、时间、用户 UUID、旧版本、新版本和节点。
- 日志默认记录规则 ID、用户 UUID、目标域名和动作，不记录密码、完整 URL 或敏感凭据。
- 对拒绝日志限速，避免被大量拒绝请求打满磁盘。
- 配置文件写入使用临时文件、fsync 和原子 rename。
- 规则编译失败时拒绝发布并保留旧配置。
- 不允许普通用户提交 regex 或任意脚本表达式。

## 10. 测试计划

### 单元测试

- exact、suffix 的域名边界。
- 大小写和末尾点号规范化。
- IPv4、IPv6、未知目标。
- exact 优先于 suffix。
- 用户规则优先于全局规则。
- allowlist 未命中时拒绝。
- 空策略和非法策略拒绝加载。

### 集成测试

- VLESS 用户 A 放行域名 X，拒绝域名 Y。
- Trojan 用户 B 使用同一域名时按 B 的策略执行。
- 不同用户同时连接，规则不会串用。
- 配置发布后新连接使用新版本，旧连接行为符合定义。
- rnode 重启后策略仍然存在。
- 发布非法配置时当前有效配置不受影响。

### 真实链路测试

至少验证：

1. 用户凭据认证成功。
2. 允许域名返回成功响应。
3. 禁止域名在出站连接建立前被拒绝。
4. 直接 IP、ECH、QUIC 不可识别时符合 `unknownTargetAction`。
5. backend、rnode、Chimera Server 三方版本和配置版本一致。

## 11. 当前 Chimera Server 实现

服务端已完成以下闭环：

- 严格配置校验、canonical JSON SHA-256 checksum、版本严格递增和回滚后防重放。
- 最近 5 个策略版本的内存与磁盘历史、原子写盘、文件与目录 fsync，以及重启后继续回滚。
- 可选本机 `nodeUuid` 校验；缺失或目标不匹配的发布包不会落盘或替换内存策略。
- `UserDomainAccessService` 的 Apply、Rollback、GetStatus，以及固定低基数决策统计。
- `enforce`、`shadow`、`disabled` 三种执行模式；默认仍为 `enforce`。`shadow` 保留完整决策与“本来会拒绝”计数，但不阻断流量；`disabled` 在身份映射后直接绕过目标分类、TLS 探测和策略计算。
- 可选 Ed25519 发布签名验证。节点本地保存可信公钥，签名缺失、未知 key ID、内容篡改或验签失败时，在写盘和替换 RuntimeState 前拒绝。
- `chimera-cli user-domain-access` 的 apply、status、rollback 操作；Status 同时返回执行模式结果、TLS 探测、Apply/Rollback 成败和签名 key ID 等固定维度信息。
- 稳定 backend UUID 优先进入访问控制与路由；协议显示身份仍用于原有流量可观测性。
- Criterion 基准覆盖策略编译、用户规模、exact/suffix 规则规模、首尾规则命中与 miss。

节点配置示例：

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
        "publicKey": "<base64-encoded 32-byte Ed25519 public key>"
      }
    ]
  },
  "userDomainAccess": {
    "version": 1,
    "generatedAt": "2026-08-04T00:00:00Z",
    "sourceBackendVersion": "bootstrap",
    "targetNodeUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "signatureAlgorithm": "ed25519",
    "signingKeyId": "backend-key-2026-01",
    "checksum": "sha256:<hex>",
    "signature": "<base64 Ed25519 signature>",
    "enforcementMode": "shadow",
    "defaultAction": "reject",
    "users": []
  }
}
```

`checksum` 对排除顶层 `checksum` 与 `signature` 字段后的 canonical JSON 计算 SHA-256，并写为 `sha256:<hex>`。签名 payload 只排除顶层 `signature`，因此会认证 checksum、签名算法、key ID、版本、目标节点和完整策略内容。动态发布要求版本严格高于运行期见过的最高版本；回滚不会降低该最高版本。未配置 `requireSignature` 时保持兼容，可继续接受只有 checksum 的旧发布包；启用后所有当前策略和持久化历史都必须通过同一验签流程。

持久化文件使用版本化 envelope，保存 `formatVersion`、`highestSeenVersion`、当前策略和最多 5 个历史策略。启动和 `--check` 会校验当前策略及全部历史策略的 checksum、签名、目标节点和版本边界；重启后历史版本仍可回滚，旧版仅包含单个策略对象的存储文件也可兼容读取。启用强制签名之前，应先确认现有落盘策略已经由受信 key 签名，否则节点会按 fail-closed 原则拒绝启动。

存储文件最大为 16 MiB。读取和覆盖都会拒绝符号链接及非普通文件；Unix 临时文件以 `0600` 创建并在 fsync 后原子替换，避免策略内容向 group/other 暴露。策略编译在容量分配前限制最多 100,000 用户、每用户 10,000 条规则、总计 1,000,000 条规则。

CLI 示例：

```bash
chimera-cli user-domain-access \
  --endpoint http://127.0.0.1:8080 \
  apply ./policy.json

chimera-cli user-domain-access \
  --endpoint 127.0.0.1:8080 \
  status

chimera-cli user-domain-access \
  --endpoint 127.0.0.1:8080 \
  rollback 11
```

### 11.1 推荐灰度顺序

1. 先以 `disabled` 发布完整身份映射和规则，确认版本、checksum、签名及节点对账正常。
2. 切换为 `shadow`，观察 `shadowRejections`、`unknownTarget`、`noUserPolicy`、TLS/ECH 探测结果和协议身份未映射情况。
3. 修正遗漏规则后，选择少量节点进入 `enforce`；拒绝率或 unknown 比例超过预设门槛时停止扩容并回滚。
4. 按固定批次扩展到 5%、25%、50% 和 100%，每批完成 Apply、Status checksum 对账、重启恢复和 Rollback 演练。
5. 稳定后再启用 `requireSignature`。密钥轮换时先同时配置新旧两个公钥，完成新 key 发布验证后再移除旧 key。

指标严格保持低基数。Status 中的主要生产字段包括：原始 allow/reject 决策、实际阻断、shadow 拒绝、disabled bypass、TLS SNI/ECH/timeout/parse outcome、探测字节数、有效 probe timeout/max bytes，以及 Apply/Rollback 成败。UUID、域名、IP 和连接 ID 不作为指标标签。

TLS ClientHello 探测默认 5ms/64KiB，可在节点本地配置为 1–100ms 和 1–256KiB。读取严格不超过配置上限，所有已捕获和未捕获字节仍按原顺序回放；`disabled` 模式完全跳过探测。调整前应通过 Status 和首包延迟基准确认影响，不应把超时无限放大。

### 11.2 性能基准

```bash
cargo bench -p chimera_server_lib --bench user_domain_access
```

基准覆盖：

- 1、100、10,000 用户的编译和末用户查找；
- 1、10、100、1,000 条 exact/suffix 规则的编译；
- 声明首条、声明末条和 miss 决策；
- release profile 下的每次决策耗时和吞吐。

短时 smoke 仅用于确认 benchmark 可执行，不能作为生产阈值。正式基线必须固定 CPU、内核、编译参数和负载，在独立重复运行中记录原始 Criterion 输出、Git commit 和硬件信息。

## 12. 跨仓库发布实现

中央 backend、Rust rnode 和 Nest 节点已完成同一发布契约：

1. backend 以用户 UUID 为主键保存当前策略，并为每个节点保存不可变版本包。
2. 版本号在 SERIALIZABLE 事务内分配；backend 使用与 Rust 一致的 canonical JSON 算法生成 checksum。
3. backend 通过 HTTPS 和短期 RS256 JWT 或预签名 Bearer token 调用节点；可选配置 CA 与客户端证书启用 mTLS。
4. Rust rnode 与 Nest 节点均暴露 `/node/user-domain-access/apply|status|rollback`，并转发到本机 Chimera gRPC。
5. 每次 Apply/Rollback 均记录 PENDING、成功或失败、响应、错误、节点、版本、checksum 和从已验证 JWT 推导的操作者。
6. 两种节点生成的 Chimera 配置都会启用 `UserDomainAccessService`。

代码完成后只剩生产部署验收：应用数据库 migration，配置节点凭据，在真实节点执行发布、状态对账、回滚、重启恢复和断网失败审计，并接入告警。
