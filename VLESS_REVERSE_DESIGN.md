# VLESS Reverse 支持设计与实施计划

- 状态：Batch A–C 已实现（feature/config/account/`0x04`/Reverse Mux wire 与 fail-closed）；Mux session、Portal runtime 与互操作尚未实现
- 更新日期：2026-09-22
- 当前本地 Xray 基线：`ref/xray-core` `v26.9.9`，提交
  `52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`
- 最新字段复核：Xray-core 官方 `main` 提交
  [`d562d8947d3175db86b4fa849742433a9876cb63`](https://github.com/XTLS/Xray-core/commit/d562d8947d3175db86b4fa849742433a9876cb63)
- 适用范围：Chimera Server 的当前 VLESS Reverse 配置、wire behavior、路由、生命周期、
  feature 隔离与互操作验证

本文固定 VLESS Reverse 的目标契约和实施顺序。它不表示当前版本已经支持 Reverse；支持状态仍以
[`examples/xray-compatible/README.md`](examples/xray-compatible/README.md) 的证据矩阵为准。

## 1. 决策摘要

Chimera 将实现 Xray 当前的 **VLESS Reverse Proxy**，不实现已经移除的根级
`reverse.bridges` / `reverse.portals` 配置。

核心决策如下：

1. Reverse 是 VLESS 的可选扩展能力，Cargo feature 命名为 `vless-reverse`。
2. `vless-reverse` 依赖基础 `vless`；依赖方向不能反转。
3. library `full` 和 app 默认/full 构建包含 `vless-reverse`。
4. `minimal-vless` 与 `minimal-vless-tls` 保持基础 VLESS，不被 Reverse 的 Mux、连接池和后台任务依赖扩张。
5. 未编译 `vless-reverse` 时，识别到当前 Reverse 字段必须返回明确 capability 错误，不能忽略。
6. 根级 legacy Reverse 无论 feature 是否启用都返回已移除错误。
7. 协议 handler 负责认证和 VLESS 编解码；Reverse worker、动态路由能力与后台任务由数据面 owner 持有。
8. 每批按单一职责、独立验证和可回滚性拆分，不使用固定行数作为拆分或验收指标。
9. 第一阶段优先交付类似 FRP 的固定 TCP 端口暴露：公网侧运行 Chimera Portal，内网侧暂用当前
   Xray Bridge；先复用现有 DokodemoDoor 和 routing，不等待 Chimera Bridge、UDP/XUDP 或完整
   transport 矩阵。

## 2. 目标与非目标

### 2.1 第一阶段目标：固定 TCP 端口暴露

- 公网 Chimera 接受内网 Xray 主动建立的 VLESS Reverse 连接。
- 公网 DokodemoDoor 监听一个固定 TCP 端口，把每条连接映射到一个固定内网目标。
- routing 按 DokodemoDoor `inboundTag` 选择 VLESS Reverse 动态 outbound tag。
- 外部访问者直接连接公网 TCP 端口，不需要安装或配置 Xray/VLESS 客户端。
- 最小实现仍须兼容 Xray 的 VLESS `0x04`、Mux TCP frame、Portal 控制 session 与 worker 状态；不能用
  Chimera 私有帧格式换取短期速度。
- 开发基线先用 loopback RAW 验证；第一阶段可部署验收至少增加一个现有可用的安全 transport，优先
  RAW/TLS。

第一阶段只要求 Chimera 实现 **Portal**。内网 **Bridge** 由固定版本 Xray 提供，因此无需先完成
Chimera VLESS outbound、Bridge monitor、sniffing、UDP/XUDP 和多 transport 主动拨号。这是交付顺序
收缩，不是改变最终兼容目标。

### 2.2 完整目标

- 接受并执行当前 Xray VLESS inbound 用户上的 `reverse.tag`。
- 接受并执行简化 VLESS outbound 上的 `reverse.tag` 与 `reverse.sniffing`。
- 实现 VLESS `RequestCommandRvs`（`0x04`）。
- 实现 Reverse 所需的 Xray Mux frame、session worker 和内部控制通道。
- 在公网侧把入站用户声明的 Reverse tag 表现为可路由的动态 outbound。
- 在内网侧把 VLESS outbound 声明的 Reverse tag 表现为进入本地 routing 的 inbound tag。
- 支持 TCP、UDP/XUDP、源地址元数据、sniffing、连接池、多线路、断线恢复和有界关闭。
- 保留现有 routing、policy、traffic、DNS、传输安全和控制面边界。
- 用固定提交构建的真实 Xray 双向验证 Chimera 的 Portal 与 Bridge 角色。

### 2.3 非目标

- 不恢复 legacy `reverse.bridges` / `reverse.portals`。
- 不把 Reverse 当作 TUN；Reverse 不依赖 TUN，也不绕过 routing/policy。
- 不因 Reverse 自动宣称全部 VLESS outbound、Vision、ML-KEM VLESS Encryption 或所有 sniffing 子能力已兼容。
- 不复制 Xray 的 Go feature registry、全局 manager 或无边界后台 goroutine 所有权。
- 不提前创建空模块、空 trait、空 Cargo feature 或没有运行时消费者的依赖。
- 不在本目标中扩展无关 outbound 协议。
- 第一阶段不提供 UDP 端口映射、动态创建/删除映射、端口范围、HTTP Host 分流或 Chimera 内网代理端；
  这些能力必须分别设计和验证，不能由“类似 FRP”一词自动推导为已支持。

## 3. 外部兼容契约

### 3.1 当前字段形态

公网侧 VLESS inbound 用户：

```json
{
  "id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
  "flow": "",
  "reverse": {
    "tag": "reverse-out"
  }
}
```

内网侧简化 VLESS outbound：

```json
{
  "protocol": "vless",
  "tag": "reverse-tunnel",
  "settings": {
    "address": "server.example.com",
    "port": 443,
    "id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
    "flow": "",
    "encryption": "none",
    "reverse": {
      "tag": "reverse-in",
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"],
        "domainsExcluded": [],
        "ipsExcluded": [],
        "metadataOnly": false,
        "routeOnly": false
      }
    }
  },
  "streamSettings": {
    "network": "raw",
    "security": "tls"
  }
}
```

当前 Xray 字段来源：

- [`infra/conf/vless.go`](https://github.com/XTLS/Xray-core/blob/d562d8947d3175db86b4fa849742433a9876cb63/infra/conf/vless.go)
- [`proxy/vless/account.proto`](https://github.com/XTLS/Xray-core/blob/d562d8947d3175db86b4fa849742433a9876cb63/proxy/vless/account.proto)
- [`common/protocol/headers.go`](https://github.com/XTLS/Xray-core/blob/d562d8947d3175db86b4fa849742433a9876cb63/common/protocol/headers.go)

### 3.2 字段规则

| 位置 | 当前字段 | 规则 |
| --- | --- | --- |
| inbound `settings.clients[]` | `reverse.tag` | 必须非空；该用户只能建立 Reverse，不得作为普通正向代理用户 |
| inbound `settings.clients[]` | `reverse.sniffing` | 不允许；存在时配置失败 |
| outbound 简化 settings | `reverse.tag` | 必须非空；作为内网侧逻辑 inbound tag |
| outbound 简化 settings | `reverse.sniffing` | 使用当前 Xray `SniffingConfig` 字段 |
| outbound `vnext[].users[]` | `reverse` | 不允许；必须提示使用简化 outbound 配置 |
| 根配置 | `reverse` | legacy feature 已移除，必须明确报错 |

省略与显式值按 Xray 当前实现处理。Chimera 不得把认识但尚未执行的行为字段当作 no-op；共享 sniffing
能力若不能执行 `metadataOnly`、FakeDNS 或某个目标覆盖协议，应返回明确的组合错误，并在支持矩阵记录，
直到对应运行时行为落地。

### 3.3 Wire behavior

- VLESS Reverse command 为 `0x04`。
- 与 MUX `0x03` 一样，Reverse request header 不携带普通 address/port。
- Xray 内部使用逻辑目标 `v1.rvs.cool` 选择该命令；Chimera 可以在内部保留类型化命令，不能要求配置该域名。
- Reverse 用户发送 TCP、UDP 或普通 MUX command 必须被拒绝。
- 没有 Reverse 授权的用户发送 `0x04` 必须被拒绝。
- 认证成功后仍须写出正常 VLESS response header，再把连接交给 Reverse Mux worker。
- malformed、truncated、未知 command 和 Mux frame 错误不能触发目标连接，也不能使 listener 退出。

## 4. 角色与数据流

### 4.1 第一阶段拓扑：公网端口映射

```text
外部 TCP 客户端
    -> 公网 Chimera DokodemoDoor（例如 0.0.0.0:8080）
    -> routing: inboundTag=public-8080, outboundTag=reverse-out
    -> Chimera VLESS Reverse Portal worker
    -> 内网 Xray 主动建立的 VLESS Reverse + Mux 物理连接
    -> Xray 以 reverse-in 作为逻辑 inbound tag 执行本地 routing
    -> Freedom 拨号 127.0.0.1:3000 或指定 LAN 服务
```

该路径不经过 TUN。公网监听、目标地址、Reverse 隧道与内网最终拨号都通过现有 session/routing/outbound
边界执行。公网 Chimera 必须保留一个普通静态 outbound，避免动态 Reverse tag 在 worker 尚未连接时
被误当成默认出口。

下面配置只描述第一阶段预期接口，在对应实现批次完成前不能直接运行，也不构成当前支持声明。公网
Chimera 的核心形态为：

```json5
{
  "inbounds": [
    {
      "tag": "reverse-control",
      "listen": "0.0.0.0",
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [{
          "id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
          "flow": "",
          "reverse": { "tag": "reverse-out" }
        }]
      },
      "streamSettings": {
        "network": "raw",
        "security": "tls",
        "tlsSettings": {
          "serverName": "public.example.com",
          "certificates": [{
            "certificateFile": "cert/fullchain.pem",
            "keyFile": "cert/privkey.pem"
          }]
        }
      }
    },
    {
      "tag": "public-8080",
      "listen": "0.0.0.0",
      "port": 8080,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 3000,
        "followRedirect": false
      },
      "streamSettings": { "network": "tcp" }
    }
  ],
  "outbounds": [{ "tag": "direct", "protocol": "freedom" }],
  "routing": {
    "rules": [{
      "type": "field",
      "inboundTag": ["public-8080"],
      "outboundTag": "reverse-out"
    }]
  }
}
```

内网 Xray 使用当前简化 VLESS outbound：

```json5
{
  "outbounds": [
    {
      "tag": "reverse-tunnel",
      "protocol": "vless",
      "settings": {
        "address": "public.example.com",
        "port": 8443,
        "id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
        "flow": "",
        "encryption": "none",
        "reverse": { "tag": "reverse-in" }
      },
      "streamSettings": {
        "network": "raw",
        "security": "tls",
        "tlsSettings": { "serverName": "public.example.com" }
      }
    },
    { "tag": "direct", "protocol": "freedom" }
  ],
  "routing": {
    "rules": [{
      "type": "field",
      "inboundTag": ["reverse-in"],
      "outboundTag": "direct"
    }]
  }
}
```

公网 DokodemoDoor 的 `address`/`port` 会成为逻辑 session 目标。示例中的 `127.0.0.1:3000` 最终由
内网 Xray 拨号，因此表示内网 Xray 所在主机的 loopback 服务，不是公网 Chimera 的 loopback。

### 4.2 公网侧 Portal

```text
外部用户 inbound
    -> routing 选择 reverse-out
    -> ReverseRegistry 查找 reverse-out 的可用 Portal worker
    -> Xray Mux session
    -> 已认证的 VLESS Reverse 物理连接
    -> 内网设备
```

公网侧 VLESS inbound 用户的 `reverse.tag` 声明一个动态 outbound 名称。配置编译阶段必须使 routing
认识该 tag，并检查它与静态 outbound、其他 Reverse tag 的冲突。运行时 worker 尚未连接时，路由仍可
解析到该能力，但 dispatch 必须快速返回“Reverse tunnel unavailable”，不能回退到默认 outbound。

### 4.3 内网侧 Bridge

```text
受监督的 VLESS Reverse outbound
    -> 主动连接公网 VLESS inbound
    -> 发送 command 0x04
    -> 建立 Mux server worker
    -> 收到公网侧创建的逻辑 session
    -> 以 reverse-in 作为 inbound tag 进入本地 routing
    -> 本地 Freedom/Blackhole/其他已支持 outbound
```

内网侧的 `reverse.tag` 与公网侧 tag 是两个本地命名空间，不要求相同。物理对应关系由同一 VLESS
Reverse 认证连接建立。

### 4.4 TCP、UDP 与元数据

- TCP session 保持双向 EOF、half-close、超时和背压。
- UDP/XUDP 保留原始 domain、IP、port、GlobalID 及目标覆盖语义。
- Mux metadata 中的 visitor source/local address 投影到 Chimera session/routing context。
- 源地址只作为路由、审计和显式 PROXY protocol 等行为输入，不能替代认证身份。
- sniffing 在内网侧 Reverse 逻辑入口执行，结果进入现有 routing 流程。

## 5. 内部架构

### 5.1 配置层

配置编译新增类型化的 `VlessReverseConfig`，并贯穿：

```text
Literal JSON
    -> VLESS inbound/outbound raw settings
    -> current-field validation
    -> VlessUser / VlessOutbound plan
    -> Reverse portal/bridge runtime plan
```

文件配置、`--check` 与未来管理 API 输入应复用同一校验函数。根级 legacy `reverse` 需要进入
`LiteralConfig` 的识别路径，以便返回 removed-feature 错误，而不是利用 serde 的默认 unknown-field
行为静默忽略。

### 5.2 协议层

VLESS codec 增加类型化 `Reverse` command。handler 只负责：

- 读取、认证和验证 request header；
- 验证用户与 command 的授权关系；
- 处理 response header 与 body addon；
- 产出“已认证 Reverse 物理连接”的显式 outcome。

handler 不直接修改全局 outbound 列表，也不永久 spawn 无 owner 的 worker。

### 5.3 Mux 层

新增的 Mux 实现负责 Xray 当前 Mux wire contract：

- frame metadata 编解码；
- New/Keep/End 等 session 状态；
- stream 与 packet transfer type；
- session ID 分配、冲突和回收；
- first payload、控制 session 与 Reverse control protobuf；
- client/server worker、worker picker 和关闭通知；
- 并发、队列、buffer 与 session 数量上限。

第一阶段虽然只转发 TCP，也不能省略 Portal 控制 session：固定版本 Xray Bridge 只有在收到并维护
Reverse control 状态后才会成为可选 worker。第一阶段可把 packet transfer、XUDP 和目标覆盖延后，
但必须完成与 Xray 互通所需的 frame codec、TCP session、控制 protobuf、ACTIVE/DRAINING 状态与 picker。

现有 `XudpMessageStream` 只覆盖当前入站 XUDP message path，不能被误认为完整 Xray Mux worker。
可复用其目标地址和 packet 语义，但不得制造第二份 GlobalID 生命周期规则。

### 5.4 ReverseRegistry

`DataPlaneRuntime` 持有窄能力 `ReverseRegistry`，其责任包括：

- 按公网侧 Reverse outbound tag 管理可用 Portal workers；
- 注册、摘除、健康检查和选择 worker；
- 在无 worker、worker 满载或关闭中时返回稳定错误；
- 向 routing/outbound dispatch 暴露窄的 TCP/UDP session 创建接口；
- 在 server shutdown 时关闭登记、排空并取消残留 worker。

Registry 不解析 JSON、不拥有 VLESS credential、不决定 routing rule，也不进入控制面 protobuf。

### 5.5 Bridge owner

每个配置的 Reverse VLESS outbound 拥有一个 bridge runtime：

- 维护物理 Reverse 连接与 Mux server workers；
- 按当前 Xray 行为在没有 worker或平均连接数超过阈值时补充 worker；
- 对拨号失败执行有界退避；
- 将逻辑 session 的 inbound tag、source/local metadata 和 sniffing plan 交给 session dispatcher；
- 在配置删除、server shutdown 或不可恢复错误时停止 monitor、关闭连接并等待任务结束。

该 owner 不能隐藏在一次普通 `connect_tcp_outbound` 调用之后永久存活。

### 5.6 路由边界

路由配置可能在 Reverse 物理连接建立前引用公网侧动态 outbound tag。因此配置编译需要同时看到：

- 静态 outbounds；
- inbound 用户声明的 Reverse outbound tags；
- balancer 和 routing rule 引用。

推荐把路由目标解析为类型化能力，而不是伪造一个可被普通 connector 误用的 VLESS outbound。
第一阶段若为减少改动使用内部 synthetic summary，必须封装为不可序列化的运行时类型，并有退出条件。

## 6. Cargo feature 设计

### 6.1 目标图

library：

```toml
[features]
vless = []
vless-reverse = ["vless"]
full = [
    # ...现有能力...
    "vless-reverse",
]
```

app：

```toml
[features]
full = ["chimera_server_lib/full"]
minimal-vless = ["chimera_server_lib/vless"]
minimal-vless-tls = ["chimera_server_lib/vless", "chimera_server_lib/tls"]
vless-reverse = ["chimera_server_lib/vless-reverse"]
```

### 6.2 语义

- `vless`：基础 VLESS inbound/outbound codec 与已有运行路径。
- `vless-reverse`：Reverse 字段、command `0x04`、Xray Mux、Portal/Bridge runtime。
- `full`：包含 Reverse，保持默认发行构建获得完整声明能力。
- `minimal-vless*`：不隐式包含 Reverse，继续用于基础 VLESS 的最小构建与故障隔离。
- app feature 只做 library forwarding，不复制实现。

只有在第一个可执行 Reverse 配置切片同时落地时才修改 manifest，避免产生无使用方的占位 feature。

### 6.3 未编译行为

| 输入 | `vless-reverse` 未启用时 |
| --- | --- |
| inbound client `reverse` | 明确提示 binary 缺少 `vless-reverse` capability |
| simplified VLESS outbound `reverse` | 同上 |
| root legacy `reverse` | 提示该 Xray feature 已移除，不能建议启用 Cargo feature |
| 无 Reverse 字段的普通 VLESS | 保持现有行为 |

## 7. 传输与安全范围

Reverse 是 VLESS account/command 能力，物理连接继续使用 VLESS outbound 的 transport/security。
实施时按实际已有能力逐项验证：

| 组合 | 计划 |
| --- | --- |
| RAW + `encryption: none` + empty flow | 第一阶段 loopback 开发与 wire 互操作基线 |
| RAW/TLS | 第一阶段部署验收；Chimera 只需已有 inbound TLS，主动拨号由 Xray Bridge 完成 |
| REALITY | Portal 侧可在现有 inbound 能力上追加验证；Chimera Bridge 方向后续单独验证 |
| WebSocket / HTTPUpgrade / gRPC | 按现有 feature 和 connector 能力分别验证 |
| Vision | 独立 VLESS flow 能力，不因 Reverse 自动宣称支持 |
| ML-KEM VLESS Encryption | 独立加密能力，不因当前字段存在而静默接受 |

如果某 transport/security 在普通 VLESS outbound 尚未实现，Reverse 配置必须返回组合错误；不能绕过安全设置
退回 RAW 明文。

## 8. 生命周期与资源约束

### 8.1 所有权

| 资源 | Owner |
| --- | --- |
| VLESS listener 与物理 inbound connection | 现有 inbound instance / connection owner |
| 公网 Portal worker pool | `ReverseRegistry` 中对应 tag 的 runtime entry |
| 内网 Bridge monitor 与物理连接 | 对应 Reverse outbound instance |
| Mux logical TCP/UDP session | 所属 Mux worker，并登记到 server/session task owner |
| sniffing 与 routed relay | 逻辑 session dispatcher |

### 8.2 启动与关闭

- 启动前完成配置、tag 冲突、feature 与组合校验。
- Bridge 启动失败必须回滚本次创建的 monitor 和物理连接。
- server shutdown 先关闭新 Reverse session 登记，再停止 monitor 和物理连接。
- 已有逻辑 session 在 grace period 内自然排空；超时后统一取消并等待结束。
- 删除 Reverse 用户或重建 inbound 时，只摘除对应 generation/tag 的 worker。
- 物理连接断开立即使 worker 不可选，不能继续接收新 session。
- 重连不得让旧 worker 在 registry 中复活。

### 8.3 资源上限

实现前为以下项目确定有文档的默认值和过载行为：

- 每个物理连接的 logical session 上限；
- 每个 Reverse tag 的 worker 上限；
- frame 与 first-payload buffer 上限；
- 控制通道与数据队列容量；
- 重连退避范围；
- idle、handshake、uplink-only 与 downlink-only timeout；
- shutdown drain 时间。

默认值优先匹配 Xray 的可观察行为；为安全增加上限时，记录外部差异并验证合法 Xray 负载。

## 9. 实施批次

批次按依赖顺序推进。每一批必须有单一可观察结果、相应测试、独立提交和下一批所需的稳定接口；
不设置固定行数门槛。若一个批次混合多个责任中心、不能独立验证或回滚风险过高，即使代码很少也应继续拆分。

第一阶段为 A–E：只交付“公网 Chimera Portal + 内网 Xray Bridge”的固定 TCP 端口暴露。F–J 完成
Chimera Bridge、UDP/XUDP 与更完整的 Reverse 兼容面。每批完成并提交后继续下一批。

### A. 基线与 feature/config 入口（已完成）

- library/app manifest 已增加 `vless-reverse` 及 full forwarding。
- `minimal-vless`、`minimal-vless-tls` 保持基础 VLESS，不隐式启用 Reverse。
- 文件配置与 gRPC/UserManager VLESS account 都识别并保留当前 inbound `reverse.tag`；未编译 capability 明确报错，legacy root `reverse` 按当前 Xray 行为拒绝，显式 `null` 仍视为未配置。
- Reverse-only inbound user 在 command `0x04` 尚未实现前不能退化为普通 forward proxy user。
- 简化 outbound `reverse` 已识别，但在 Chimera Bridge 落地前返回明确的“该角色尚未实现”错误；`vnext.users[].reverse` 按当前 Xray 配置约束明确拒绝。
- feature 开关两侧的普通 VLESS 构建与定向测试已验证；Batch A 不声明 `0x04`、Mux、Portal runtime 或互操作支持。

### B. VLESS account 与 command（已完成）

- `VlessUser`、gRPC/UserManager 以及静态/动态 VLESS outbound account wire payload 保留 Reverse 配置；Bridge runtime 尚未实现时 outbound decode 明确 fail closed。
- protobuf payload 已对齐 `reverse = 7`，不会把 Reverse account 静默降级为普通 VLESS account。
- codec 已实现 command `0x04` 的无地址 request header，并映射到 Xray 的 `v1.rvs.cool` 逻辑目标；当前认证通过后在 Portal runtime 边界返回明确 Unsupported。
- 已覆盖普通用户/Reverse 用户 × forward/`0x04` 的授权矩阵、Vision 用户快照路径，以及 Reverse header 每个截断前缀的 `UnexpectedEof` 行为。
- Batch B 不包含 Xray Mux frame、Reverse control session、worker picker 或 Portal 数据面；这些从 Batch C 开始。

### C. Mux frame codec（已完成）

- 已增加独立 Reverse Mux wire codec，对齐 Xray frame metadata 的 session ID、NEW/KEEP/END/KEEPALIVE、option bits、TCP/UDP target、port-then-address、stream/packet transfer type，以及 Reverse NEW frame 的 source/local metadata；现有 XUDP runtime 未在本批改写。
- 已对齐 `xray.app.reverse.Control` protobuf 的 `ACTIVE = 0` / `DRAIN = 1` 和 `random = 99` wire 字段，并对未知 control state fail closed。
- 固定字节向量覆盖普通 TCP NEW frame、带 source/local 的 Reverse NEW frame 和 ACTIVE/DRAIN control；同时覆盖 TCP/UDP roundtrip 与 UDP GlobalID。
- metadata 长度上限保持 Xray 的 512 bytes；未知 session status、截断地址、非法 metadata shape 和重复 NEW session ID 明确失败，END 后允许 ID 重用。
- Batch C 只提供 wire primitive 与序列校验；尚未创建 client worker、session manager、picker、heartbeat/control session owner 或数据面 task，这些属于 Batch D。

### D. Mux TCP session core

- 先实现 Portal 所需的 client worker、session manager、picker、TCP EOF/half-close 与背压。
- 控制 session 决定 worker 是否可选；未 ACTIVE、已 DRAINING 或已关闭的 worker 不得接收新连接。
- worker 关闭传播和无可用 worker 错误。
- 并发与 buffer 上限测试。

### E. 公网 Portal runtime

- VLESS inbound Reverse outcome 交给数据面注册。
- Reverse tag 进入 routing target resolution。
- 实现动态 worker 注册、选择、摘除和 unavailable 行为。
- 普通静态 outbound 与 Reverse tag 冲突在启动前失败。
- 复用现有 DokodemoDoor 固定 TCP 目标与 `inboundTag` routing，完成公网端口到内网服务的纵向路径。
- 用固定 Xray Bridge 验证 RAW loopback 与 RAW/TLS，形成第一阶段可用里程碑。

### F. 内网 Bridge runtime

- 简化 VLESS outbound 启动受监督 Reverse monitor。
- 复用 VLESS dial/transport/security，发送 command `0x04`。
- 补全 Mux server worker，按 `reverse.tag` 注入 inbound context。
- 覆盖失败退避、断线重连、多 worker 和 shutdown。

### G. UDP/XUDP

- 实现 packet session、目标覆盖、GlobalID 关联和清理。
- 避免与现有全局 XUDP registry 形成两套竞争 owner。

### H. Sniffing 与源地址

- 复用共享 sniffing compiler 和 dispatcher。
- 传播 source/local metadata、routing user、policy identity 和 traffic context。
- 验证 HTTP Host、TLS SNI、routeOnly、排除规则和 PROXY protocol 使用方。

### I. 动态管理与可观测性

- AddUser/RemoveUser 对 Reverse 授权和 worker 的生效语义对齐固定 Xray 基线。
- 增加安全的 tag、worker/session count、重连和失败原因指标。
- 日志不得包含 UUID、认证 payload、private key 或完整配置。

### J. 真实互操作与文档收口

- 双向运行固定 Xray：Xray Bridge -> Chimera Portal、Chimera Bridge -> Xray Portal。
- 更新 materialized examples、支持矩阵、配置文档和 ARCHITECTURE 实施状态。
- 未验证组合保持 Partial/Missing，不因主路径通过改成完整支持。

## 10. 测试与验证矩阵

### 10.1 配置测试

- inbound `reverse.tag` 有效、空值、重复值和静态 outbound 冲突；
- inbound `reverse.sniffing` 明确失败；
- simplified outbound Reverse 成功；
- `vnext[].users[].reverse` 明确失败；
- root legacy Reverse 明确失败；
- feature 未编译时当前字段明确失败；
- 普通 VLESS 配置在 feature 开关两侧保持等价；
- `reverse.sniffing` 每个当前字段的省略值、显式值和非法值。

### 10.2 Wire 与运行时测试

- 第一阶段 DokodemoDoor `public-port -> reverse-out -> internal-target` 纵向路径；
- command `0x04` 编解码和 response header；
- Reverse 用户不能正向代理；普通用户不能建 Reverse；
- Mux TCP small payload、large payload、half-close、双向 EOF；
- 控制 session ACTIVE/DRAINING、worker 尚未激活和失效摘除；
- malformed/truncated frame、未知状态、重复 session ID；
- 无 worker、满载、worker 关闭竞态；
- Xray Bridge 先启动、后启动、断线重连与公网 listener 持续健康；
- 多个外部并发 TCP 连接映射到同一内网目标；
- 后续阶段覆盖 UDP/XUDP 多目标、域名保留、GlobalID、断开重附着；
- 多条物理 Reverse 连接的选择和故障摘除；
- Bridge 失败退避、恢复、删除配置和 whole-server shutdown；
- source IP、sniffing、routing、policy 和 traffic 统计。

### 10.3 构建组合

```sh
cargo tree -p chimera_server_app --no-default-features --features minimal-vless -e features
cargo check -p chimera_server_app --no-default-features --features minimal-vless
cargo check -p chimera_server_app --no-default-features --features minimal-vless-tls
cargo check -p chimera_server_app --no-default-features --features vless-reverse
cargo check -p chimera_server_app --no-default-features --features vless-reverse,tls
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p chimera_server_lib --lib
```

Batch A 落地后已执行 `minimal-vless` 与 `vless-reverse` app 构建、Reverse 定向单元测试，以及 full-minus-`vless-reverse` 的 gRPC fail-closed 测试；完整发布门槛仍按本节其余命令和 AGENTS 要求执行。

### 10.4 真实 Xray 互操作

第一阶段先完成表中前两行；其余行属于完整 Reverse 后续验收：

| 阶段 | Portal | Bridge | 流量 | 结果要求 |
| --- | --- | --- | --- | --- |
| 第一阶段 | Chimera | Xray 固定提交 | TCP/RAW loopback | echo、large payload、half-close、断线后恢复 |
| 第一阶段 | Chimera | Xray 固定提交 | TCP/RAW+TLS | 公网端口可用，认证失败不建目标连接 |
| 后续 | Xray 固定提交 | Chimera | TCP | echo、large payload、half-close、断线后恢复 |
| 后续 | Chimera | Xray 固定提交 | UDP/XUDP | 多目标、域名、session 清理 |
| 后续 | Xray 固定提交 | Chimera | UDP/XUDP | 同上 |
| 全阶段 | Chimera | Xray 固定提交 | invalid auth/command | 不建目标连接，listener 保持健康 |
| 后续 | Chimera/Xray | Xray/Chimera | 多连接/多线路 | 并发与故障切换，无泄漏、无错误 worker 复活 |

记录 Xray commit、binary version/hash、Go/Rust 工具链、平台、feature、脱敏配置、命令和结果。

## 11. 安全与诊断

- Reverse 专用用户不能退化成普通 forward proxy 用户。
- 不可用或未编译安全配置不能退回明文。
- tag、协议、配置字段路径可以记录；UUID、认证 payload 和私钥不得记录。
- malformed Mux input 使用有界分配，长度计算检查溢出。
- worker/session 数量和队列必须有背压或明确拒绝行为。
- 公网侧必须保留明确默认 outbound，避免未命中流量误入 Reverse。
- Reverse routing 仍执行 Chimera routing、policy、DNS 和 traffic 约束，不提供绕过入口。

## 12. 支持声明与完成标准

### 12.1 状态定义

- **Missing**：字段或运行时不存在。
- **Config-only**：能够正确接受/拒绝字段，但无数据面行为。
- **Runtime-covered**：本地测试覆盖完整路径，但没有真实 Xray 证据。
- **Xray-verified**：固定版本 Xray 双端互操作通过。
- **Partial**：只验证明确列出的 transport/security/TCP/UDP 组合。

### 12.2 第一阶段可用目标：FRP-like TCP 端口暴露

第一阶段不是“完整 VLESS Reverse”发布，但可以作为明确标注范围的可用能力交付。至少要求：

1. 当前 inbound user `reverse.tag`、未编译诊断与 legacy rejection 完整；
2. 当前简化 outbound `reverse` 被识别，并在 Chimera Bridge 尚未实现时明确拒绝；
3. `vless-reverse` / full / minimal feature 图验证；
4. Chimera Portal 能接受固定版本 Xray Bridge 的 command `0x04`、Mux TCP 和控制 session；
5. 一个 DokodemoDoor 固定公网 TCP 端口能经 `inboundTag -> reverse-out` 到达固定内网目标；
6. RAW loopback 和 RAW/TLS 的 Xray Bridge -> Chimera Portal 真实互操作通过；
7. 覆盖 small/large payload、并发连接、half-close、无 worker、错误认证、Bridge 断线与重连、server shutdown；
8. 配置示例明确公网监听、内网目标和凭据/证书前提；日志不泄露 UUID、认证 payload 或私钥；
9. 支持矩阵只声明 Portal + TCP + 已验证 transport，不暗示 Chimera Bridge、UDP/XUDP、动态映射、
   Vision、ML-KEM 或其他 transport 已完成。

### 12.3 完整 Reverse 可发布目标

完整 Reverse 兼容发布在第一阶段基础上至少还要求：

1. Chimera Portal 与 Bridge 两个角色均可用；
2. TCP 与 UDP/XUDP 均有本地运行时覆盖；
3. RAW + `encryption:none` + empty flow 双向 Xray 验证；
4. 至少一个生产可用的安全 transport 双向验证；
5. 断线恢复、多 worker、无 worker、错误认证和 shutdown 覆盖；
6. sniffing、源地址与动态用户行为按支持范围验证；
7. 支持矩阵逐组合声明，不暗示 Vision、ML-KEM 或未验证 transport 已完成。

## 13. 提交与交接规则

- 每批只提交一个责任或可观察行为，不混入无关清理和依赖升级。
- 每批先检查工作区，保留其他贡献者改动。
- 每批运行能证明该边界的最小检查，记录实际执行和测试数量。
- 一个批次是否继续拆分由职责、验证边界、风险和审阅性决定，不由固定行数决定。
- 按批次提交后继续下一步；出现基线冲突、需要扩大产品范围或无法保持可编译时再停止报告。
- 不自动 push、发布、打 tag 或启动 release workflow。
- 完成重大阶段后同步 ARCHITECTURE、兼容矩阵和实际验证证据。

## 14. 与 Xray 的内部实现差异

Xray 当前 VLESS Reverse 复用 `app/reverse` 的 Portal/Bridge worker 和 `common/mux`，并通过动态
outbound manager 注册公网侧 tag。Chimera 不复制其全局 feature manager，而是使用现有
`DataPlaneRuntime`、routing publication 和 task owner：

- 外部 JSON 字段、VLESS command、Mux wire、路由身份和错误边界以 Xray 为契约；
- 内部 worker registry、Rust task ownership 和 shutdown sequencing 按 Chimera 架构实现；
- 任何可观察差异必须有失败证据、设计理由、测试和兼容矩阵说明。

参考路径：

- `ref/xray-core/proxy/vless/inbound/inbound.go`
- `ref/xray-core/proxy/vless/outbound/outbound.go`
- `ref/xray-core/common/mux/`
- `ref/xray-core/app/reverse/`
