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

1. **Stage 2A（当前）**：落地协议骨架、控制面数据结构、edge/tunnel agent 新模块的骨干代码，确保 can build；暂不启用实际流量切换。
2. **Stage 2B**：完成 QUIC 实现、HAProxy 集成、控制面 API；提供 end-to-end MVP。
3. **Stage 2C**：增加 WebSocket fallback、压缩、metrics、UI 展示等。

本设计文档将随着实现更新，作为 Stage 2 交付的基础。
