# Tunnel 架构设计（Stage 2）

本文描述内网穿透分组在 Stage 2 的整体方案，涵盖协议、控制平面扩展、Edge/Tunnel Agent 职责以及密钥管理。该设计在 Stage 1 基础上继续演进，目标是让边缘节点统一运行 `edge-agent`（同时负责 OpenResty/HAProxy 与隧道服务端），内网节点仅运行 `tunnel-agent` 作为隧道客户端。

## 1. 隧道能力概述

| 角色            | 运行环境                   | 核心职责 |
| --------------- | -------------------------- | -------- |
| Control Plane   | Master 控制面              | 生成 / 下发配置、分配 tunnel-agent key、追踪隧道状态 |
| Edge Agent      | 边缘节点（公网）           | 渲染 OpenResty/HAProxy 配置；运行隧道服务端（QUIC/WebSocket）；接收来自 tunnel-agent 的内网流量并转发到公网入口 |
| Tunnel Agent    | 内网主机（无公网）         | 使用 key 认证，主动连接隧道服务端；按控制面下发的映射将本地 TCP/UDP 服务暴露出去 |

特性需求：

- 支持 TCP/UDP 双向透传。通过 QUIC 默认提供加密/心跳/断线重连能力，WebSocket 作为备用传输。
- 多路复用：单条 QUIC 连接上承载多个逻辑流，减少握手开销。
- 心跳 & 重连：隧道客户端定期发送 ping，edge 端追踪最后活跃时间，超时即清理；断线后客户端会在同分组内随机挑选新的 edge 重新建连。
- 压缩：对流量可选压缩，按路由配置开启。

## 2. Key & 身份认证

- **创建**：在控制面为 tunnel-agent 生成唯一 key（随机 32 byte → base64）。key 与 `nodeID` 绑定，默认长期有效。
- **握手**：tunnel-agent 建连时发送 `{ nodeID, key, version, preferredProtocols }`，edge-agent 校验 key 有效性/分组是否匹配，否则拒绝。
- **刷新**：仅在需要吊销或替换时手动刷新；控制面记录 key 版本。当 key 被刷新后，edge-agent 会拒绝旧 key 的连接。
- **最小暴露**：key 仅在创建时展示一次，安装脚本将其写入 `/etc/anyproxy/tunnel-agent.env`。

## 3. 控制平面扩展

### 3.1 数据结构

- `TunnelAgentConfig`：`{ nodeID, keyHash, groupID, enabled, localServices[] }`
- `TunnelGroup`：`{ id, name, edgeNodeIDs[], tunnelPort, protocols }`
- `EdgeSnapshot` 增加 `TunnelIngress[]`：每个 ingress 包含 `groupID`, `listenAddress`, `allowedKeys`.
- `TunnelSnapshot` 包含 `groupID`, `edgeCandidates[]`, `localServices[]`, `agentKey`.

### 3.2 API & 前端

- `POST /v1/tunnel-agents` 创建 agent，返回 key。
- `POST /v1/tunnel-agents/{id}/refresh-key` 刷新 key。
- `POST /v1/tunnel-groups` 管理分组，指定 edge 成员与监听端口。
- UI 展示分组、key、连接状态、最近心跳。

## 4. Edge-Agent 设计

新增模块 `tunnelserver`：

- 监听 `TunnelIngress` 指定的端口（默认 QUIC，fallback WebSocket）。
- 管理 `session`：`key` → `connection` → `streams`。每个流映射一个 HAProxy 后端连接。
- 对接 HAProxy：HAProxy backend 改为连接 `127.0.0.1:<bridge-port>`，由 tunnelserver 接管并转发到对应的 tunnel-agent 流。
- 心跳：服务端维护 `lastSeen`，超时断开；支持压缩/加密选项。

配置流程：

1. 控制面下发 `TunnelIngress`+`TunnelRoutes` 到 edge-agent。
2. edge-agent 渲染 HAProxy 配置，将特定 backend 指向 tunnelserver。
3. HAProxy 收到公网请求 → backend → tunnelserver → 对应 tunnel-agent → 内网服务。

## 5. Tunnel-Agent 设计

- 启动后读取 `agentKey`/`groupID`/`edgeCandidates`。
- 建立 QUIC 连接（`groupID` 对应的监听地址），发送握手并注册 `localServices`。
- 本地监听端口（或直接连接本地服务），将流量封装在隧道流中。
- 支持多 edge 候选：按 DNS/配置随机挑选，失败后回退其他节点。
- 心跳：固定间隔发送 ping，携带 session stats；edge 端 ack。
- 断线重连：指数退避，最长 60s；重连成功后重新注册服务。

## 6. 安装与运行

- **Edge 节点**：`ANYPROXY_NODE_TYPE=edge`，安装 edge-agent / OpenResty / HAProxy，新增 `ANYPROXY_TUNNEL_PORT` 指明监听端口（默认 4433）。
- **Tunnel 节点**：`ANYPROXY_NODE_TYPE=tunnel`，新增 `ANYPROXY_AGENT_KEY`、`ANYPROXY_GROUP_ID`、`ANYPROXY_EDGE_CANDIDATES`。脚本将 key 写入 `/etc/anyproxy/tunnel-agent.env`，systemd 单元读取。

## 7. 阶段性交付计划

### Stage 2A（当前） – 隧道数据面 MVP

目标：打通 edge ↔ tunnel-agent 的最小可用通道，Lay out 基础配置结构。

#### 范围

1. **edge-agent 与 HAProxy**
   - 调整 HAProxy 模板：穿透型路由的 backend 统一指向本地 `tunnel-server`（如 `127.0.0.1:<bridge-port>`），由 `tunnel-server` 负责将请求映射到具体 tunnel-agent。
   - `tunnelServerManager` 根据 snapshot 启停服务器，维护 `listenAddr -> keyHash -> SessionInfo`，并暴露 bridge 端口供 HAProxy 使用。
   - `configstore`/snapshot 新增 `TunnelIngress`，描述每个分组在 edge 侧需要开放的监听地址、允许的 key、所属节点等；`edge-agent` 基于它渲染/更新 `tunnelServer`。

2. **tunnel-server 基础实现**
   - 接受来自 tunnel-agent 的连接（先用 TCP 骨干，后续迭代 QUIC/WebSocket），完成握手、key 校验、会话注册/心跳。
   - 接入 HAProxy：监听本地 bridge 端口，建立 “HAProxy -> tunnelServer -> tunnelAgent” 的 TCP pipeline（先不做多路复用）。

3. **配置结构**
   - Snapshot 中包含 `TunnelIngress`、`TunnelAgents` 的 key 映射，edge-agent 只需根据 snapshot 启停服务，不需要本地持久状态。
   - TunnelRoute.Target 暂解释为 “目的 agent service ID”，真正的地址由 tunnel-server 内部映射。

> TIps：Stage 2A 目的在于打通最小链路，允许先用简单的 TCP 转发和 key map，压缩/多路复用/QUIC 等放在 Stage 2B。

### Stage 2B – tunnel-agent 替换 & 端到端联调

1. **tunnel-agent**
   - 改为真正的隧道客户端：读取 `services[]`，本地监听 TCP 端口，把流量封装在 tunnel 流中（先支持 TCP，多路复用后再扩展 UDP）。
   - 实现 handshake / heartbeat / 重连逻辑，优先使用 QUIC，必要时 fallback WebSocket。
   - 安装脚本/CLI：生成命令时自动注入 `agentKey`/`groupId`/`edgeCandidates`，systemd 单元使用 env 变量启动。

2. **edge-agent / tunnel-server**
   - 完整接入多路复用（单连接多流）、心跳超时、key 版本管理。
   - HAProxy/`tunnel-server` 对接：支持 TCP → tunnel 流的桥接，UDP 先延后。

3. **E2E 验证**
   - 通过控制面创建 tunnelGroup/tunnelAgent，部署 edge/tunnel 节点，验证从公网到内网的 TCP 流量闭环。

### Stage 2C – 控制平面与 UI

1. **API**
   - 扩展 `/v1/tunnel-groups`、`/v1/tunnel-agents`：创建/修改/刷新 key、查询在线会话。
   - 提供 CLI/前端接口，生成包含 key 的安装命令。

2. **前端**
   - “隧道分组 & Agent” 管理界面（列表、状态、刷新 key、安装命令）。
   - 会话/心跳视图：展示每个 agent 的在线状态、最后心跳、绑定 edge。

3. **配置联动**
   - Edge/tunnel agent 在 UI 操作后自动刷新 snapshot，确保配置闭环。

### Stage 2D – 监控 & 告警

1. **指标**
   - Master：总隧道数、在线 agent 数、key 刷新次数等。
   - Edge-agent：每个 tunnel-server 的活跃会话、心跳延迟、失败次数。
   - Tunnel-agent：重连次数、心跳 RTT、本地服务健康。

2. **执法**
   - 导出 Prometheus metrics、webhook 通知（如 key 验证失败、连接超时）。
   - 统一日志格式，记录 handshake、断线、告警事件，便于排查。

---

本设计文档会随着每个 Stage 的实现阶段性更新。当前重点是 Stage 2A（隧道数据面 MVP），完成后再推进后续阶段。
