# Chimera Server 与 Xray-core 当前能力差距分析

## 1. 文档目的

本文基于当前 Chimera Server 源码和仓库内固定的 Xray-core 参考实现，对两者的协议、传输、出站、DNS、路由、控制面和运行时能力进行一次重新盘点。

本文重点回答三个问题：

1. Xray-core 当前支持、但 Chimera Server 尚未支持的能力有哪些；
2. 哪些能力在 Chimera 中已经存在，但只实现了部分 Xray 语义；
3. 下一轮迭代应该从哪里开始，才能以最小风险获得最大的兼容收益。

本文不是把所有 Xray 功能都列为必做项。优先级会根据以下标准排序：

- 是否直接影响常见 Xray JSON 配置的可加载性；
- 是否直接影响真实流量能否转发；
- 是否是后续其他能力的公共运行时基础；
- 是否会明显扩大数据面复杂度或平台依赖；
- 是否可以通过小切片、可回滚方式逐步实现。

---

## 2. 对比基线

### 2.1 Xray-core 基线

仓库内参考实现：

```text
ref/xray-core
```

本次核对版本：

```text
5ca6f4b7d4dc
Xray-core v26.7.28
2026-07-28
```

### 2.2 Chimera Server 基线

分析分支：

```text
feat/xray-parity-next
```

该分支基于已经完成用户域名访问控制及生产加固的 Chimera Server 继续推进。

### 2.3 判断标准

本文将能力分为四类：

- **已支持**：配置、运行时和主要数据面行为已经存在，并有对应测试；
- **大部分支持**：主路径可用，但仍缺部分配置字段、边界行为或跨协议组合；
- **部分支持**：配置字段可能能解析，或存在局部实现，但无法覆盖 Xray 的主要运行语义；
- **未支持**：没有对应配置模型、运行时对象或数据面实现。

“字段可以被 JSON 解析”不等于“功能已支持”。例如当前 `sniffing`、`policy` 某些字段可以进入 LiteralConfig，但没有进入实际运行时决策，因此仍应归类为未支持或部分支持。

---

## 3. 总体结论

当前 Chimera Server 的能力分布并不均匀：

- **入站协议已经较强**；
- **路由、统计和动态控制面已经较完整**；
- **出站数据面是当前最大的结构性缺口**；
- **通用 sniffing、Xray DNS/FakeDNS、mKCP、TUN、Reverse 等仍明显不足**；
- **XHTTP 已经不再是旧文档描述的“独立 raw upstream inbound”，但仍只完成了部分 Xray transport 语义**。

最重要的结论是：

> 下一轮不应继续优先增加新的入站协议，而应先建立通用 Outbound Runtime，并让路由真正能够选择 VLESS、VMess、Trojan、SOCKS、HTTP、Shadowsocks 等代理出站。

当前路由可以正确选出 outbound tag，但真实 TCP/UDP 数据面只接受：

```text
freedom
blackhole
```

如果路由选到尚未实现的代理出站，当前实现会在配置编译或动态安装阶段 fail-closed。VLESS TCP、Trojan TCP/UDP 与 SOCKS5 TCP/UDP 已经形成真实 connector，说明通用 Outbound Runtime 路线有效，但剩余代理协议仍是最值得优先补齐的公共基础。

---

## 4. 当前已支持或大部分支持的 Xray 能力

## 4.1 入站协议

当前 Chimera 已经具备以下入站：

- VLESS；
- VMess；
- Trojan；
- SOCKS；
- HTTP；
- Dokodemo Door；
- Shadowsocks；
- Shadowsocks 2022，包括 AEAD 2022、UDP 和部分 EIH 多用户能力；
- Hysteria2；
- TUIC v5，虽然 TUIC 不是当前 Xray-core proxy 目录中的标准协议，但属于 Chimera 的扩展能力；
- Mixed inbound。

其中以下行为也已经存在：

- VLESS TCP、UDP、XUDP；
- VMess TCP、UDP；
- Trojan TCP 与多目标 UDP；
- SOCKS TCP、UDP；
- HTTP CONNECT 和透明 origin-form；
- Dokodemo TCP/UDP、followRedirect；
- Shadowsocks TCP/UDP、2022 防重放；
- VLESS/Trojan fallback 与 PROXY protocol 输出；
- 用户身份进入统计、路由和用户域名访问控制。

因此，当前最主要的问题不是“没有常见入站”，而是部分 Xray 新字段和高级运行时语义尚未接入。

## 4.2 常用传输和安全层

当前已经支持或基本支持：

- TCP；
- WebSocket；
- HTTP Upgrade；
- gRPC transport；
- TLS；
- REALITY；
- XHTTP 的 VLESS inbound 包装；
- QUIC 数据面，用于 TUIC 和 Hysteria2。

## 4.3 路由

当前路由实现已经覆盖大量 Xray 语义：

- `domainStrategy`：`AsIs`、`IPIfNonMatch`、`IPOnDemand`；
- inbound tag；
- user；
- protocol；
- domain；
- CIDR 和 GeoIP；
- GeoSite；
- source IP、source port；
- local IP、local port；
- target port；
- TCP/UDP network；
- process name/path/folder；
- attributes；
- reverse CIDR/GeoIP 规则；
- webhook；
- dynamic AddRule/RemoveRule；
- balancer override；
- Random；
- RoundRobin；
- LeastPing；
- LeastLoad；
- fallbackTag；
- observatory 状态参与 balancer 选择。

路由层本身已经接近可用，当前主要受制于可供选择的真实 outbound 太少。

## 4.4 Xray gRPC 控制面

Chimera 当前提供与 Xray 同名的主要服务：

- HandlerService；
- StatsService；
- RoutingService；
- ObservatoryService；
- LoggerService。

另外还增加了：

- UserDomainAccessService。

这意味着 rnode/backend 已经可以复用较多 Xray 控制面契约。

---

## 5. P0：出站数据面缺口

这是当前最重要的差距。

## 5.1 当前 OutboundItem 已具备主干字段，但高级 sender 语义仍有限

静态 outbound 已能保存并严格编译：

- `settings`；
- `streamSettings`；
- outbound user/account；
- server endpoint；
- TCP/TLS/REALITY/WebSocket/HTTP Upgrade/gRPC transport。

HandlerService 也能将 Xray `SenderConfig` 转换为同一静态模型。当前仍明确拒绝：

- `sendThrough` / `via`；
- mux；
- proxy chaining；
- sockopt；
- mask/QUIC 参数；
- 非 `AsIs` target strategy；
- XHTTP outbound transport。

## 5.2 当前真实可执行 outbound

当前数据面支持：

- `freedom`；
- `blackhole`；
- VLESS TCP；
- VMess TCP；
- Trojan TCP/UDP；
- SOCKS5 TCP/UDP；
- HTTP CONNECT TCP；
- Shadowsocks legacy AEAD TCP/UDP。

VLESS、VMess、Trojan、SOCKS、HTTP 与 Shadowsocks legacy AEAD 均支持静态 JSON、动态 HandlerService 和原始 domain/IP target；TCP 协议复用 TCP/TLS/REALITY/WebSocket/HTTP Upgrade/gRPC transport pipeline。VMess 当前真实 Xray 验收覆盖 plain none 与 TLS+AES-128-GCM；Trojan TCP/UDP 覆盖 plain 与 TLS，UDP 文本与 1200-byte datagram 均已通过 Xray 真实互通；SOCKS TCP/UDP 覆盖 plain no-auth 与 TLS+password，UDP 文本与 1200-byte datagram 均已通过 Xray 真实互通；HTTP 覆盖 plain no-auth 与 TLS+Basic Auth；Shadowsocks TCP 覆盖 plain AES-128-GCM 与 TLS+ChaCha20-IETF-Poly1305，UDP 覆盖 SOCKS5 UDP → Chimera → Xray → echo 的文本与 1200-byte datagram，并覆盖 TUIC datagram 与 UDP-over-stream response adapter。VLESS/VMess 的代理 UDP、HTTP 非 CONNECT 转发、Shadowsocks XChaCha/2022/EIH，以及 Trojan/SOCKS/Shadowsocks 的持久 UDP association 均尚未完成。

下面这些 Xray outbound 尚未形成真实 connector：

- Hysteria；
- WireGuard；
- DNS outbound；
- Loopback；
- Shadowsocks 2022 outbound。

对尚未支持的协议，静态启动和 HandlerService 安装会在数据面可见前拒绝，不再保存“可列出但不可执行”的虚假 outbound。

## 5.3 Freedom 只实现了最小连接

Xray Freedom 还支持：

- `domainStrategy`；
- redirect/destinationOverride；
- user level；
- PROXY protocol；
- TLS fragment；
- UDP/TCP noise；
- final rules；
- FinalMask；
- socket options；
- interface/mark；
- source bind。

Chimera 当前 Freedom 本质上是：

```text
resolve target
→ create TCP/UDP socket
→ direct connect/send
```

尚未实现上述大多数设置。

## 5.4 Blackhole 只实现了直接丢弃

Xray Blackhole 支持不同 response，例如 HTTP response。

Chimera 当前只返回 blocked/None，没有 Xray HTTPResponse 行为。

## 5.5 为什么 Outbound 应优先

Outbound 是以下能力的共同依赖：

- 路由到代理节点；
- balancer 的真实多出口；
- observatory 对代理出站测速；
- DNS 经指定 outbound 查询；
- chained proxy；
- loopback；
- WireGuard；
- reverse；
- XHTTP downloadSettings；
- 测试完整 Xray 配置。

因此建议先建立统一 Outbound Runtime，而不是逐个在 `outbound.rs` 中继续扩展 match 分支。

---

## 6. 推荐的 Outbound Runtime 结构

建议引入分层结构：

```text
Literal outbound config
        ↓
Compiled OutboundConfig
        ↓
OutboundRegistry(tag → connector)
        ↓
OutboundSession
        ↓
Transport connector
        ↓
Protocol encoder
        ↓
TCP stream / UDP association
```

可以定义类似：

```rust
trait TcpOutboundConnector {
    async fn connect(
        &self,
        session: &OutboundSession,
        target: &NetLocation,
    ) -> io::Result<Box<dyn AsyncStream>>;
}
```

```rust
trait UdpOutboundConnector {
    async fn open_association(
        &self,
        session: &OutboundSession,
    ) -> io::Result<Box<dyn UdpAssociation>>;
}
```

`OutboundSession` 至少应包含：

- inbound tag；
- selected outbound tag；
- stable user UUID / routing identity；
- source address；
- original target domain/IP/port；
- TCP/UDP network；
- sniffed protocol/domain；
- resolved addresses；
- process metadata；
- connection attributes。

第一阶段不要立即做所有协议。先建立 registry 与 trait，并用 Freedom/Blackhole 适配当前逻辑，确保行为不变。

---

## 7. P0：通用 Sniffing 尚未实现

## 7.1 当前状态

当前 LiteralConfig 可以解析：

```json
"sniffing": { ... }
```

但该字段没有进入 ServerConfig、TrafficContext 或通用 dispatcher。

当前用户域名访问控制中存在一个有限的 TLS ClientHello 探测器，但它只用于：

- 当协议原始目标是 IP 或未知目标时尝试获取 SNI；
- 决定用户域名策略；
- 有界读取并回放字节。

它不等同于 Xray sniffing。

## 7.2 Xray sniffing 仍缺的语义

Xray 支持：

- `enabled`；
- `destOverride`；
- HTTP；
- TLS；
- QUIC；
- FakeDNS；
- `metadataOnly`；
- `routeOnly`；
- `domainsExcluded`；
- `ipsExcluded`。

Chimera 尚未形成一个可以向路由和 dispatcher 提供 sniffed destination/protocol 的公共层。

## 7.3 应避免的错误实现

不能简单把用户域名访问控制中的 5ms TLS probe 扩大成通用 sniffing：

- HTTP 需要解析首行和 Host；
- TLS 需要跨 record 处理；
- QUIC Initial 需要单独解密和解析；
- FakeDNS 依赖映射表；
- routeOnly 与 destOverride 的行为不同；
- 所有已读取数据必须完整回放；
- VLESS 等客户端可能等待服务端响应后才发送内层 ClientHello，不能无界阻塞。

建议新增独立 `SniffingContext`，与用户域名访问控制共享解析器，但不共享策略语义。

---

## 8. P0/P1：DNS 与 FakeDNS 缺口

## 8.1 当前已有能力

Chimera 当前 resolver 已经具备：

- native resolver；
- 多 resolver 顺序 fallback；
- 正缓存；
- 负缓存；
- 并发查询合并；
- TTL；
- timeout；
- IPv4/IPv6 排序偏好；
- 缓存统计。

这些是良好的底层基础。

## 8.2 与 Xray DNS app 的差距

尚未支持：

- 顶层 `dns` 配置；
- `hosts` / staticHosts；
- 多 nameserver 及每 server 独立规则；
- domain matcher；
- expected IP；
- unexpected IP；
- `skipFallback`；
- `finalQuery`；
- `actPrior` / `actUnprior`；
- per-server timeout；
- per-server queryStrategy；
- 全局 queryStrategy；
- disableFallback；
- disableFallbackIfMatch；
- enableParallelQuery；
- disableCache；
- serveStale；
- expired TTL；
- nameserver tag；
- 通过指定 outbound 发起 DNS；
- DNS outbound；
- FakeDNS / FakeIP 池；
- FakeDNS 与 sniffing/routing 的映射恢复。

## 8.3 推荐顺序

建议按以下顺序推进：

1. typed DNS config；
2. static hosts；
3. nameserver 列表和 query strategy；
4. domain-scoped nameserver；
5. expected/unexpected IP；
6. parallel/fallback 行为；
7. DNS outbound；
8. FakeDNS；
9. FakeDNS sniffing 恢复。

DNS outbound 依赖通用 Outbound Runtime，因此不建议早于 outbound 基础层。

---

## 9. P1：XHTTP 剩余差距

旧版 `docs/xhttp_gap_vs_xray.zh.md` 中部分结论已经过时。

当前 XHTTP 已经完成：

- `protocol=xhttp` 已禁用，要求使用 `protocol=vless + streamSettings.network=xhttp`；
- 已经具备 inner VLESS handler；
- `stream-one`；
- `stream-up`；
- `packet-up`；
- `auto`；
- session/seq 的 path/query/header/cookie placement；
- uplink body/header/query/cookie placement；
- `uplinkHTTPMethod`；
- `noSSEHeader`；
- xPadding placement/method/obfs；
- max post bytes；
- buffered posts；
- min post interval；
- session TTL；
- queue bound；
- TLS；
- REALITY；
- 流关闭后的 session 清理。

仍缺或仅做配置保存的能力：

- XHTTP 作为 VMess、Trojan、SOCKS、HTTP、Shadowsocks 等协议的通用 transport；
- HTTP/3 listener；
- UNIX socket listener；
- `downloadSettings` 真实运行语义；
- `xmux` 真实连接复用语义；
- `noGRPCHeader` 在数据面中的完整语义；
- browser dialer；
- 客户端 outbound XHTTP；
- Xray browser client 行为；
- 完整 h1/h2/h3 兼容矩阵；
- 与 Xray-core 的真实互通矩阵。

其中 `downloadSettings` 和 `xmux` 当前主要在配置和 HandlerService encode/decode 层存在，没有进入 `beginning/xhttp.rs` 数据面。

---

## 10. P1：mKCP 未支持

Xray 仍包含完整 mKCP transport：

- listener；
- dialer；
- segment；
- congestion/window；
- header obfuscation；
- seed；
- MTU/TTI；
- uplink/downlink capacity；
- read/write buffer；
- TCP/UDP fake header。

Chimera 当前把 `network=kcp` 分类为 QUIC transport，但没有 mKCP wire protocol 实现。这种分类只能作为占位，不代表兼容。

因此：

> 当前任何 Xray `streamSettings.network = "kcp"` 配置都不应被视为已支持。

建议在真正实现之前 fail-closed，而不是映射为 QUIC。

mKCP 是高复杂度传输，应排在 outbound、sniffing 和 DNS 之后。

---

## 11. P1：SocketConfig 和 streamSettings 高级字段

Xray SocketConfig 支持大量系统级选项：

- mark；
- TCP Fast Open；
- original destination；
- accept PROXY protocol；
- dialer proxy；
- TCP keepalive interval/idle；
- TCP congestion；
- interface；
- IPv6-only；
- TCP window clamp；
- TCP user timeout；
- TCP max segment；
- penetrate；
- MPTCP；
- custom sockopt；
- trusted X-Forwarded-For；
- Happy Eyeballs 参数。

Chimera 底层 socket 工具有：

- reuse port；
- bind interface；
- transparent/original destination 的部分 Linux 支持；
- TCP nodelay。

但这些能力尚未形成 Xray `sockopt` 配置模型，也没有完整进入 inbound/outbound 构造链。

建议先做最常用字段：

1. interface；
2. mark；
3. TCP keepalive；
4. TCP Fast Open；
5. acceptProxyProtocol；
6. original destination；
7. Happy Eyeballs 参数；
8. congestion；
9. MPTCP 和 custom sockopt。

系统级字段必须严格按平台 gate，不能为了“配置可解析”在不支持的平台静默忽略。

---

## 12. P1：Xray Policy 配置目前没有运行语义

当前顶层配置可以解析：

```json
"policy": {
  "levels": {},
  "system": {}
}
```

但 `PolicyConfig` 仅保存为 `HashMap<String, Value>`，后续运行时没有使用。

Xray policy 主要包括：

- handshake timeout；
- connection idle timeout；
- uplink-only timeout；
- downlink-only timeout；
- per-user uplink stats；
- per-user downlink stats；
- user online stats；
- per-connection buffer；
- inbound uplink/downlink stats；
- outbound uplink/downlink stats；
- user level 关联。

Chimera 已经有自己的统计和部分超时，但没有按 Xray level/system policy 统一驱动。

建议：

- 先建立 typed PolicyConfig；
- 将 user level 保存到认证用户；
- 先接 timeout；
- 再接 stats switch；
- 最后处理 buffer policy。

---

## 13. P1：入站高级字段缺口

## 13.1 VLESS 新字段

Xray 当前 VLESS inbound 除 users/fallback/decryption 外，还包含：

- `xorMode`；
- `secondsFrom`；
- `secondsTo`；
- `padding`。

Chimera 当前主要支持：

- users；
- fallback；
- decryption=none；
- Vision；
- XUDP；
- TLS/REALITY/WS/gRPC/HTTPUpgrade/XHTTP。

上述时间窗口、XOR 和 padding 字段尚未对齐。

## 13.2 userLevel

Dokodemo、HTTP、SOCKS、Freedom、DNS 等 Xray 配置包含 user level。

Chimera 当前用户模型重点保存 UUID/email/username/password identity，没有统一 level policy。

## 13.3 allocate

Literal inbound 可以解析 `allocate`，但未进入运行时。

Xray AllocationStrategy 的 refresh/concurrency 行为当前未支持。

---

## 14. P2：TUN inbound 未支持

Xray 当前包含 `proxy/tun`，Chimera 没有 TUN inbound。

TUN 涉及：

- 平台设备创建；
- route 配置；
- IP stack；
- UDP/TCP 会话映射；
- DNS 劫持；
- MTU；
- privilege/capability；
- Linux/macOS/Windows 差异。

该能力复杂且平台相关，不适合作为下一切片。

若后续实现，建议复用成熟 userspace stack 或单独 crate，并与核心代理数据面隔离。

---

## 15. P2：Reverse 未支持

Xray reverse app 支持：

- bridge；
- portal；
- domain-based reverse tunnel；
- control channel；
- mux session。

Chimera 当前没有对应顶层配置、运行时或控制 channel。

Reverse 强依赖：

- 通用 outbound；
- mux；
- loopback/dispatcher；
- 长连接管理；
- 连接恢复。

应在 outbound 与 mux 完成后再考虑。

---

## 16. P2：Loopback 未支持

Xray loopback outbound 可以把流量重新注入指定 inbound，并支持 sniffing。

Chimera 当前没有 loopback outbound。

它依赖安全的 dispatcher 递归保护，否则容易产生路由环路。

实现时至少需要：

- hop count；
- visited outbound/inbound tags；
- 最大重入深度；
- cycle detection；
- route trace。

---

## 17. P2：WireGuard outbound 未支持

Xray WireGuard 支持：

- userspace/kernel 模式；
- peer；
- PSK；
- allowed IP；
- keepalive；
- MTU；
- endpoint；
- noKernelTun。

Chimera 当前没有 WireGuard outbound。

该能力不应直接塞入通用 TCP connector，而应作为独立虚拟网络 outbound。

---

## 18. P2：Metrics HTTP 服务未支持

Xray metrics app 提供独立 listen/tag，通常用于 HTTP metrics。

Chimera 当前已有：

- StatsService；
- ObservatoryService；
- 用户域名访问控制固定维度 stats；
- resolver stats；
- routing stats。

但没有统一的 Prometheus/HTTP metrics endpoint。

建议在指标命名稳定后增加只读 HTTP endpoint，并严格控制 label 基数。

---

## 19. P2：FinalMask、Tagged、Browser Dialer 和 TCP Header

Xray transport 中还存在：

- FinalMask；
- Tagged transport；
- Browser Dialer；
- TCP header obfuscation；
- transport masks。

Chimera 当前未支持这些高级 transport 组合。

这些功能通常不应早于：

- 通用 outbound；
- transport registry；
- XHTTP client；
- sockopt；
- 统一 stream pipeline。

---

## 20. 建议优先级

## P0：直接影响主流配置和数据面

1. 通用 Outbound Runtime；
2. Freedom/Blackhole 迁移到新 registry；
3. VLESS TCP outbound；（已完成）
4. Trojan TCP/UDP outbound；（已完成）
5. VMess TCP outbound；（已完成）
6. SOCKS outbound；（TCP 与 UDP ASSOCIATE 已完成）
7. HTTP outbound；（CONNECT TCP 已完成）
8. Shadowsocks TCP/UDP outbound；（legacy AEAD TCP/UDP 主路径与 TUIC response adapter 已完成）
9. 通用 sniffing context；
10. typed DNS config + static hosts + nameserver rules；
11. DNS outbound。

## P1：高价值兼容能力

1. VLESS/VMess UDP outbound；
2. outbound TLS/REALITY/WS/HTTPUpgrade/gRPC；
3. XHTTP outbound；
4. XHTTP downloadSettings/xmux；
5. XHTTP H3/UNIX；
6. FakeDNS；
7. Xray policy level/timeouts；
8. sockopt 常用字段；
9. mKCP。

## P2：扩展与平台能力

1. TUN；
2. Reverse；
3. Loopback；
4. WireGuard；
5. metrics HTTP endpoint；
6. FinalMask；
7. browser dialer；
8. tagged transport；
9. advanced TCP headers/masks。

---

## 21. 推荐的下一实现切片

建议下一切片不要直接实现 VLESS outbound，而是先建立基础边界：

### Slice 1：Outbound Registry 基础层

当前实现状态：基础 registry 已完成。RuntimeState 现在原子保存有序 outbound 摘要和 tag → `Arc` connector 映射；Freedom/Blackhole 的 TCP/UDP 选择已通过 registry 执行；静态启动、`--check` 和动态 HandlerService 会在安装前拒绝未知协议和重复 tag；RemoveOutbound 不会使已取得 connector 的活动会话失效。`OutboundSession`、通用 connector trait、typed settings 和 observatory connector 能力仍属于下一阶段。

目标：

- 新增 typed outbound config；
- 新增 OutboundSession；
- 新增 connector trait；
- 新增 tag → connector registry；（已完成）
- Freedom/Blackhole 迁移到 registry；（已完成）
- TCP/UDP 路由改为通过 registry 执行；（已完成）
- 保持现有行为不变；（已完成）
- HandlerService Add/RemoveOutbound 原子更新 registry；（已完成）
- observatory 从 registry 读取 connector 能力。

明确不做：

- VLESS wire protocol；
- VMess wire protocol；
- TLS/WS/gRPC outbound；
- DNS app；
- mux。

验收：

- 现有 Freedom/Blackhole 测试全部通过；
- routed missing outbound fail-closed；
- unsupported outbound 在编译/安装阶段拒绝，而不是连接时才失败；
- AddOutbound 失败不污染 registry；
- RemoveOutbound 不影响已持有 Arc 的活动连接；
- TCP/UDP 均走统一 selection；
- 全量 workspace 测试、fmt、Clippy 通过。

### Slice 2：VLESS TCP Plain Outbound

当前实现状态：已完成。静态配置同时接受 Xray 标准 `vnext` 结构和简化 `address/port/id` 结构；动态 HandlerService 接受 `xray.proxy.vless.outbound.Config`、VLESS Account 与 Xray SenderConfig TypedMessage，并由同一 registry 编译路径校验。数据面保留原始 domain/IP target，写入标准 VLESS TCP 请求头，业务数据可立即上行；标准响应头在第一次下行读取时惰性消费，避免等待服务端响应导致首包死锁。当前接受单 endpoint、单用户、`flow=""`、`encryption=none`，并可组合 TCP、TLS、REALITY、WebSocket、HTTP Upgrade 和 gRPC transport；UDP、Vision、Mux、via/proxy chaining、socket options、mask、QUIC 参数及非 AsIs target strategy 均 fail-closed。已通过 mock 协议级 roundtrip，以及 `SOCKS → Chimera → VLESS outbound → Xray 26.2.6 inbound → echo` 的真实进程互通，覆盖 IP、域名和 64KiB payload。

目标：

- 支持单 endpoint；（已完成）
- 支持单用户 UUID；（已完成）
- 支持原始 domain/IP target；（已完成）
- 支持 VLESS TCP command；（已完成）
- 支持首包；（已完成）
- 支持标准 response；（已完成，惰性消费 response header）
- 先只允许 `network=tcp`、`security=none`；（已完成，其他组合 fail-closed）
- 与本地 Xray-core VLESS inbound 做双向互通测试。（已完成，Xray 26.2.6）

### Slice 3：Outbound Transport Pipeline

当前实现状态：TCP、TLS、REALITY、WebSocket、HTTP Upgrade 与 gRPC 子切片均已完成。Registry 在安装阶段将静态 `streamSettings` 或动态 HandlerService `SenderConfig` 编译成同一不可变的“安全层 + 应用传输层”状态，TCP connector 先建立底层连接，再应用 TLS/REALITY，随后进行 WebSocket、HTTP Upgrade 或 gRPC HTTP/2 建链，最后写入 VLESS 请求头。TLS 当前支持系统根证书或内联 `AUTHORITY_VERIFY`/`certificates[].usage=verify` CA、SNI、ALPN、TLS 1.2/1.3 版本边界和 session resumption 开关；`allowInsecure`、fingerprint、证书 pin、ECH、客户端证书、证书文件和未知字段均 fail-closed。REALITY 复用现有客户端握手状态机，支持 `serverName/publicKey/shortId/cipherSuites`，并明确拒绝尚未实现的 uTLS fingerprint 与 spiderX。WebSocket 复用现有二进制帧流，支持 host、规范化 path 和普通自定义 headers，严格验证 101/Upgrade/Connection/Sec-WebSocket-Accept 与客户端/服务端 masking 方向；early data、heartbeat、proxy protocol、保留握手头和 REALITY+WS 均 fail-closed。HTTP Upgrade 使用 Xray 的伪 WebSocket 101 握手，握手后保持原始字节流，支持 host、path、普通 headers 和 TLS 组合；early data、proxy protocol、Host/Connection/Upgrade 覆盖与 REALITY 组合 fail-closed。gRPC 复用现有 Hunk 编解码，通过 Hyper HTTP/2 建立单个双向 `/{serviceName}/Tun`，默认 `GunService`，支持 authority、userAgent、普通 serviceName，并可叠加 TLS 或 REALITY；客户端在后台等待响应头，避免 Go gRPC 服务读取首个 Hunk 前不回 header 导致的双向流死锁。multiMode、keepalive/window 调优和自定义 method path fail-closed。动态 SenderConfig 会原子安装并由 ListOutbounds 重建回显；`via`、proxy chaining、Mux、socket options、mask、QUIC 参数和非 AsIs target strategy 在 registry 变更前拒绝。所有 transport 组合均已通过 Xray 26.2.6 真实进程互通，覆盖 IP、域名和 64KiB payload。

目标：

- TCP；（已完成）
- TLS；（静态配置已完成）
- REALITY；（静态配置核心握手已完成）
- WebSocket；（静态 WS/WSS 已完成）
- HTTP Upgrade；（静态 plain/TLS 已完成）
- gRPC；（静态 plain/TLS/REALITY 已完成）
- transport pipeline 复用于 VLESS/VMess/Trojan/SOCKS/HTTP。（全部已接入 TCP 主路径）

### Slice 4：Trojan TCP/UDP Outbound

当前实现状态：TCP 与 UDP 主路径已完成。静态配置支持 Xray 标准 `servers:[...]` 与简化 `address/port/password`；动态 HandlerService 支持 `xray.proxy.trojan.ClientConfig`、Trojan Account 与通用 SenderConfig，并由同一 registry 编译器原子安装。TCP 数据面发送 SHA-224 小写十六进制密码摘要、CRLF、command `0x01`、原始 domain/IPv4/IPv6 target 与结尾 CRLF，之后直接透传双向字节流。UDP executor 通过同一 transport pipeline 建立流，发送相同认证摘要、command `0x03` 和 association target；每个 datagram 使用 `address + port + u16 payload length + CRLF + payload` 分帧，60 秒内有界读取同格式响应并恢复原始 source。该 one-shot executor 已接入固定目标、目标化消息、session/XUDP、SOCKS5 inbound、Dokodemo、Shadowsocks inbound、Hysteria2 与 TUIC response channel。仅允许单 endpoint、单密码和空 flow；非空或已移除 flow 继续 fail-closed，持久 UDP association 尚未实现。Trojan connector 复用完整 TCP/TLS/REALITY/WebSocket/HTTP Upgrade/gRPC transport pipeline；plain 与 TLS 均已通过 Xray 26.2.6 真实进程 TCP/UDP 互通，TCP 覆盖 IP、域名和 64KiB，UDP 覆盖文本与 1200-byte datagram。

目标：

- 支持标准与简化静态配置；（已完成）
- 支持动态 ClientConfig、SenderConfig 和 ListOutbounds；（已完成）
- 支持 SHA-224 hex 认证头与 TCP/UDP command；（已完成）
- 保留原始 domain/IP target 与 UDP response source；（已完成）
- 复用共享 transport pipeline；（已完成）
- 覆盖固定/目标化/session、SOCKS5、Dokodemo、Shadowsocks inbound、Hysteria2 与 TUIC；（已完成）
- 非空 flow fail-closed；（已完成）
- 与 Xray Trojan inbound 做 plain/TLS TCP/UDP 双向互通测试。（已完成）
- 持久 UDP association；（待完成）

### Slice 5：SOCKS5 TCP/UDP Outbound

当前实现状态：已完成 TCP 与 UDP 主路径。静态配置支持 Xray 标准 `servers:[{address,port,users}]` 与简化 `address/port/user/pass`；动态 HandlerService 支持 `xray.proxy.socks.ClientConfig`、SOCKS Account 与通用 SenderConfig，并通过 ListOutbounds 回显。TCP 客户端实现 SOCKS5 method negotiation、NO_AUTH、RFC1929 用户名密码认证、CONNECT command、IPv4/IPv6/domain target、reply code 映射和 bind address 完整消费；CONNECT 响应之后的同包业务字节不会丢失。UDP executor 通过完整 transport pipeline 建立控制流，执行相同认证后发送 `UDP ASSOCIATE 0.0.0.0:0`，严格解析 IPv4/IPv6/domain relay；relay 返回 unspecified IP 时回退到代理 endpoint IP。每个请求保持控制流存活，创建匹配地址族的 one-shot UDP socket，按 RFC 1928 编码目标与 payload，并仅接受配置 relay socket 的响应；响应严格要求 `RSV=0`、`FRAG=0`，恢复原始 IPv4/IPv6/domain source 与 payload。该 executor 已接入固定目标、目标化消息、session/XUDP、SOCKS5 inbound、Dokodemo、Shadowsocks inbound、Hysteria2 与 TUIC response channel。仅允许单服务器和最多一个账户，用户名/密码长度在安装或握手前限制为 255 字节；SOCKS UDP fragmentation 与持久 association 尚未实现。plain no-auth 与 TLS+password 已通过 Xray 26.2.6 真实进程 TCP/UDP 互通，TCP 覆盖 IP、域名和 64KiB，UDP 覆盖文本与 1200-byte datagram。

目标：

- 支持 NO_AUTH 与 RFC1929 用户名密码；（已完成）
- 支持标准与简化静态配置；（已完成）
- 支持动态 ClientConfig、SenderConfig 与 ListOutbounds；（已完成）
- 严格校验 SOCKS 版本、method、auth status、CONNECT/UDP ASSOCIATE reply、reserved byte 和 address type；（已完成）
- 保留原始 domain/IP target、CONNECT 后首包和 UDP response source；（已完成）
- 复用共享 transport pipeline；（已完成）
- 支持 RFC 1928 UDP ASSOCIATE 与 RSV/FRAG fail-closed；（已完成）
- 覆盖固定/目标化/session、SOCKS5、Dokodemo、Shadowsocks inbound、Hysteria2 与 TUIC；（已完成）
- 与 Xray SOCKS inbound 做 plain no-auth 与 TLS+password 的 TCP/UDP 双向互通测试。（已完成）
- 持久 UDP association 与 fragmentation；（待完成）

### Slice 6：HTTP CONNECT TCP Outbound

当前实现状态：已完成。静态配置支持 Xray 标准 `servers:[{address,port,users}]/headers` 与简化 `address/port/user/pass/headers`；动态 HandlerService 支持 `xray.proxy.http.ClientConfig`、HTTP Account、重复 header 检测、通用 SenderConfig 与 ListOutbounds 回显。客户端发送 HTTP/1.1 CONNECT、规范化 Host authority、可选 Basic Proxy-Authorization、Proxy-Connection keep-alive 与经过严格校验的自定义 header；IPv6 target 使用方括号 authority。响应头限制为 64KiB，仅接受 HTTP/1.0/1.1 的 2xx，407 映射权限错误、502/503 映射连接拒绝、408/504 映射超时，CONNECT 后同包业务字节不会丢失。Host、Proxy-Authorization、Proxy-Connection、Connection、Content-Length 和 Transfer-Encoding 等保留头以及 CR/LF 注入均在安装前 fail-closed。connector 复用完整 transport pipeline。plain no-auth 与 TLS+Basic Auth 已通过 Xray 26.2.6 真实进程互通，覆盖 IP、域名、自定义 header 和 64KiB payload。

目标：

- 支持单服务器、无认证与 Basic Proxy-Authorization；（已完成）
- 支持标准与简化静态配置及安全自定义 header；（已完成）
- 支持动态 ClientConfig、SenderConfig 与 ListOutbounds；（已完成）
- 严格校验响应版本、状态码、64KiB 头部边界与保留 header；（已完成）
- 保留原始 domain/IP target、IPv6 authority 与 CONNECT 后首包；（已完成）
- 复用共享 transport pipeline；（已完成）
- 非 CONNECT forward proxy 语义 fail-closed；（已完成）
- 与 Xray HTTP inbound 做 plain no-auth 与 TLS+Basic Auth 双向互通测试。（已完成）

### Slice 7：Shadowsocks Legacy AEAD TCP/UDP Outbound

当前实现状态：TCP 与 UDP 主路径已完成。静态配置支持 Xray 标准 `servers:[{address,port,method,password}]` 与简化 `address/port/method/password`；动态 HandlerService 支持 `xray.proxy.shadowsocks.ClientConfig`、legacy Account、通用 SenderConfig 与 ListOutbounds 回显。Registry 仅接受 AES-128-GCM、AES-256-GCM 和 ChaCha20-IETF-Poly1305，并在安装时通过 EVP_BytesToKey/MD5 派生 master key。TCP 数据面复用入站已验证的 Shadowsocks AEAD codec，建立共享 transport 后发送随机 salt、加密长度与加密 payload，并将原始 domain/IPv4/IPv6 target 放入首个明文 chunk；响应方向独立读取服务端 salt并解密 chunk。UDP 数据面复用同一用户配置构建 packet codec，每个请求生成独立 salt，密文包含目标地址和 payload；响应解密恢复源地址与 payload，并通过 salt checker 拒绝 replay。当前 UDP executor 为 one-shot socket，只允许 plain proxy endpoint，覆盖固定目标、目标化消息、session/XUDP、SOCKS5、Dokodemo、Shadowsocks inbound、Hysteria2 与 TUIC response framing。TUIC adapter 同时支持 QUIC datagram 与 UDP-over-stream，两个方向共享原子 packet ID；datagram 回包按当前 QUIC 最大 datagram size 分片，stream 回包通过共享 SendStream 串行写入。XChaCha、`iv_check=true`、2022/EIH 和持久 UDP association 尚未实现。三种 cipher 已通过本地 TCP/UDP roundtrip、tamper 与 replay 回归；plain AES-128-GCM 与 TLS+ChaCha20-IETF-Poly1305 TCP 已通过 Xray 26.2.6 真实互通，SOCKS5 UDP → Chimera → Xray → echo 已通过文本与 1200-byte datagram 真实互通；TUIC datagram 与 UDP-over-stream 已通过本地 Shadowsocks AEAD 真实往返。32KiB 单 datagram 超出该 Xray legacy UDP 路径的实际处理边界，因此未作为兼容目标。

目标：

- 支持 AES-128-GCM、AES-256-GCM 与 ChaCha20-IETF-Poly1305；（已完成）
- 支持标准与简化静态配置；（已完成）
- 支持动态 ClientConfig、SenderConfig 与 ListOutbounds；（已完成）
- 复用现有 salt/subkey/nonce/chunk codec，并保持请求响应独立 salt；（已完成）
- 保留原始 domain/IP target；（已完成）
- 支持 legacy AEAD UDP packet 加密、响应源地址恢复、tamper 与 replay 拒绝；（已完成）
- 覆盖固定/目标化/session、SOCKS5、Dokodemo、Shadowsocks inbound 与 Hysteria2；（已完成）
- XChaCha、2022/EIH、iv_check 和持久 UDP association fail-closed；TUIC adapter 已完成。
- 与 Xray Shadowsocks inbound 做 plain AES、TLS+ChaCha TCP 以及 SOCKS5 UDP 双向互通测试。（已完成）

### Slice 8：VMess TCP Outbound

当前实现状态：已完成。静态配置支持 Xray 标准 `vnext:[{address,port,users}]` 与简化 `address/port/id/security`；动态 HandlerService 支持 `xray.proxy.vmess.outbound.Config`、VMess Account、通用 SenderConfig 与 ListOutbounds 回显。客户端生成带时间戳、随机数和 CRC32C 的 AuthID，经 VMess KDF 和 AES-ECB 加密；请求长度和请求头分别通过标准 AEAD KDF 路径加密，头部包含随机数据 IV/key、响应认证字节、TCP command、原始 domain/IPv4/IPv6 target 与 FNV1a 校验。数据层支持 `none`、AES-128-GCM 和 ChaCha20-Poly1305，响应 key/IV 按 SHA-256 派生并复用现有 `VmessStream` 交换读写方向。AUTO、AES-CFB、alterId、experiments、Mux 和 UDP 均在安装或路由阶段 fail-closed。三种 security 已通过本地客户端/服务端双向协议 roundtrip；plain none 与 TLS+AES-128-GCM 已通过 Xray 26.2.6 真实进程互通，覆盖 IP、域名和 64KiB payload。

目标：

- 支持 VMess AEAD AuthID、请求长度和请求头；（已完成）
- 支持 none、AES-128-GCM 与 ChaCha20-Poly1305 body；（已完成）
- 支持标准与简化静态配置；（已完成）
- 支持动态 Config、Account、SenderConfig 与 ListOutbounds；（已完成）
- 保留原始 domain/IP target，并正确消费 response header；（已完成）
- 复用共享 transport pipeline；（已完成）
- AUTO、AES-CFB、alterId、experiments、Mux 和 UDP fail-closed；（已完成）
- 与 Xray VMess inbound 做 plain none 与 TLS+AES 双向互通测试。（已完成）

---

## 22. 为什么不建议下一步直接做 mKCP 或 TUN

mKCP 和 TUN 都是高复杂度、平台或 wire-protocol 风险较高的能力。

当前最大的实际问题是：

```text
路由已经选出了代理 outbound
但运行时无法连接该 outbound
```

在这个问题未解决前，实现 mKCP 或 TUN 并不能让主流代理拓扑工作，反而会扩大测试矩阵。

Outbound Registry 完成后，新增协议和 transport 才能以插件式方式持续迭代。

---

## 23. 需要修正的旧文档结论

`docs/xhttp_gap_vs_xray.zh.md` 的基线较旧，其中以下内容已经不再准确：

- “XHTTP 只能作为独立 protocol”；
- “没有 inner protocol handler”；
- “没有 mode”；
- “没有 placement”；
- “没有流控和 TTL”；
- “没有 TLS/REALITY”。

当前真实剩余差距应以本文第 9 节为准。

建议后续将旧文档标记为 historical，不再作为当前执行清单。

---

## 24. Definition of Done

某项 Xray 兼容能力只有满足以下条件才能标记完成：

1. Xray JSON 字段被 typed config 严格解析；
2. 非法字段组合 fail-closed；
3. 配置进入 RuntimeState，而不是只停留在 LiteralConfig；
4. TCP/UDP 数据面真实执行；
5. HandlerService encode/decode 保留配置；
6. 静态配置与动态 Add/Remove 行为一致；
7. 与固定 Xray-core 参考版本完成真实互通；
8. 已读首包完整回放；
9. 失败不污染当前运行状态；
10. 有协议级单测和至少一个本地 E2E；
11. 最小 feature 构建通过；
12. 全量 workspace 测试和 Clippy 通过；
13. 文档和 TODO 同步。

---

## 25. 最终建议

从当前源码成熟度看，Chimera 已经跨过“入站协议不足”的阶段，正在进入“完整代理运行时”的阶段。

下一阶段的主线应该是：

```text
Outbound Registry
→ VLESS outbound
→ 通用 outbound transport
→ VMess/HTTP/Shadowsocks outbound 与 SOCKS UDP
→ VLESS/VMess UDP 与 Shadowsocks 2022/EIH
→ 通用 sniffing
→ Xray DNS/FakeDNS
→ XHTTP client 与完整 xmux/download
→ mKCP/TUN/Reverse/WireGuard
```

其中最值得立即开始的是：

> Slice 1：Outbound Registry 基础层，并将现有 Freedom/Blackhole 无行为变化地迁入新架构。

这是当前收益最大、风险最低、能为后续最多功能提供基础的迭代。