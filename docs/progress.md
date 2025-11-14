# 阶段进展纪要

## 已完成工作
1. **安装与边缘渲染**
   - `edge-install.sh` 现仅针对边缘节点部署 `edge-agent`（同时渲染 OpenResty/HAProxy）并允许自定义 HAProxy reload；tunnel 节点只下发 `tunnel-agent`。
   - `scripts/generate-node-command.sh`/`docs/deploy.md` 已支持自动注入 `ANYPROXY_AGENT_KEY`、`ANYPROXY_TUNNEL_GROUP_ID` 等变量，便于生成带 Key 的安装命令。

2. **控制平面能力**
   - `configstore`（Memory/ETCD）新增 `TunnelGroup`、`TunnelAgent`、`TunnelAgentService` 模型，提供 CRUD、密钥生成/刷新、快照同步。
   - `internal/api/server.go` 暴露 `/v1/tunnel-groups`、`/v1/tunnel-agents` 及 `refresh-key` 接口，管理面可以创建分组、发放/吊销 tunnel-agent key。

3. **Agent 与隧道协议骨架**
   - `edge-agent` 同时渲染 HTTP/HAProxy，并根据 `TunnelGroup` 自动拉起本地隧道服务端，动态校验 Key。
   - `internal/tunnel/protocol` + `client/server` 完成 handshake/heartbeat framing，`tunnel-agent` 侧已具备握手、心跳与重连基础逻辑。
4. **Edge Agent 版本管理**
   - 控制平面存储 `agentVersion/agentDesiredVersion`，前端可针对节点设置目标版本；`edge-agent` 会从 `/install/binaries/<version>/edge_linux_amd64.tar.gz` 下载新二进制并原地 `exec`，成功后记录最近升级时间。
4. **隧道数据面 Stage 2A**
   - `tunnel-server` 接入 HAProxy bridge 端口与控制/数据信道，支持按服务下发命令、令 `tunnel-agent` 主动建立数据通道。
   - `tunnel-agent` 从控制面快照读取自身配置（group/edge candidates/services），使用 agent key 主动连接 edge 节点并完成双向转发。
   - 安装脚本与 CLI 支持注入 `ANYPROXY_AGENT_KEY`、`ANYPROXY_EDGE_CANDIDATES` 等变量，自动持久化 key 并输出新的 systemd 单元。

## 下一步计划
1. **隧道数据通道**：在 edge-agent 中将 HAProxy backend 接入 tunnel server，完成 TCP/UDP 双向流量转发；tunnel-agent 则根据配置监听本地端口，将数据封装到 QUIC/WebSocket 多路复用通道中。
2. **控制平面与 UI 对接**：前端/CLI 调用新增 API，支持创建分组、查询会话、刷新 key，并把生成的 key 直接投喂安装命令。
3. **监控与容错**：为控制面、edge-agent、tunnel-agent 增加心跳/会话指标、日志以及异常告警；补充 webhook/metrics 方便观测。
4. **文档与运维体验**：完善隧道部署指南（key 流程、常见问题、灰度策略），提供脚本/模板快速批量注册内网节点。
