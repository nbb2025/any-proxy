# any-proxy

any-proxy 是一个面向内部 CDN / 内网穿透场景的控制平面与节点代理套件。控制平面使用 Go 编写，边缘节点采用 Nginx/OpenResty，通过分布式配置同步、长轮询和模板渲染实现高可用域名转发与 TCP 隧道暴露。

## 组件简介

- **Control Plane (`cmd/control-plane`)**：维护域名/隧道路由，提供 `/v1/config/...` REST 接口。核心配置（edge/tunnel snapshot）通过 etcd Watch 下发，节点/分组等管理面数据存放在 PostgreSQL，双写保持等价。
- **Edge Agent (`cmd/edge-agent`)**：监听与自身节点匹配的 HTTP/S 路由，渲染 OpenResty `nginx.conf` 并执行可选的 reload 命令，同时上报当前运行的 Agent 版本，控制平面可为单个节点设置目标版本并触发自升级。
- **Tunnel Agent (`cmd/tunnel-agent`)**：作为内网客户端读取控制面快照，使用分配的 agent key 主动连接 edge 节点的 tunnel-server，将本地 TCP/UDP 服务暴露出去。
- **Templates (`pkg/templates`)**：默认的 HTTP / Stream 模板，可通过 `-template` 参数覆盖以注入自定义指令。

## 快速开始

1. **启动依赖（etcd + PostgreSQL）**

   推荐直接使用仓库自带的 Compose：
   ```sh
   docker compose -f deploy/docker-compose.yml up -d postgres etcd
   ```
   或者自行启动：
   ```sh
   docker run -d --name anyproxy-pg -p 5432:5432 \
     -e POSTGRES_PASSWORD=anyproxy -e POSTGRES_DB=anyproxy postgres:16
   docker run -d --name anyproxy-etcd -p 2379:2379 -p 2380:2380 \
     quay.io/coreos/etcd:v3.5.15 \
     /usr/local/bin/etcd --name=etcd0 --data-dir=/etcd-data \
     --advertise-client-urls=http://0.0.0.0:2379 \
     --listen-client-urls=http://0.0.0.0:2379 \
     --listen-peer-urls=http://0.0.0.0:2380 \
     --initial-advertise-peer-urls=http://etcd:2380 \
     --initial-cluster=etcd0=http://etcd:2380
   ```

2. **运行控制平面（需要 etcd + PG）**

   ```sh
   go run ./cmd/control-plane \
     -listen :8080 \
     -etcd-endpoints http://127.0.0.1:2379 \
     -pg-dsn postgres://anyproxy:anyproxy@127.0.0.1:5432/anyproxy?sslmode=disable \
     -seed configs/bootstrap.example.json
   ```

3. **启动 Edge Agent**

   ```sh
   go run ./cmd/edge-agent \
     -control-plane http://127.0.0.1:8080 \
     -node-id edge-a \
     -output ./deploy/generated/nginx-edge.conf \
     -reload "openresty -s reload" \
     -dry-run
   ```

4. **启动 Tunnel Agent**

  ```sh
  go run ./cmd/tunnel-agent \
     -control-plane http://127.0.0.1:8080 \
     -node-id tunnel-a \
     -agent-key <agent-secret> \
     -group-id tg-default \
     -edge 127.0.0.1:4433 \
     -edge 127.0.0.1:4434
  ```

默认 `tunnel-agent` 会在版本号变化时重新拉起数据通道；将多个 `-edge` 参数指向可达的 edge 节点可实现自动重连。

### Agent 版本管理

1. 编译或安装时可以通过 `--agent-version`（或 `ANYPROXY_AGENT_VERSION` 环境变量）覆盖当前 Edge Agent 的语义版本；若留空或传入 `latest`，Agent 会自动上报自身编译时的版本号。
2. Edge Agent 在注册心跳时会将 `agentVersion` 上报到控制平面，前端会显示“当前版本 / 目标版本 / 最近升级时间”。
3. 在“边缘节点”页面点击“设置版本”，即可写入 `agentDesiredVersion`。留空则清除目标版本。
4. Agent 发现 `agentDesiredVersion` 与自身 `agentVersion` 不一致时，会从控制平面下载 `/install/binaries/<version>/edge_linux_amd64.tar.gz`，原地替换运行中的可执行文件并 `exec` 自身，从而完成远程升级。
5. 升级成功后，Agent 会清空目标版本并记录 `lastUpgradeAt`。如下载/执行失败，将自动重试。

### `edgectl` 本地管理工具

执行 `edge-install.sh` 部署 Edge 节点时，会自动将 `edgectl` 安装到 `/usr/local/bin/edgectl` 并写入 `/etc/anyproxy/edgectl.env` 状态。常用命令：

- `sudo edgectl upgrade --version v0.3.6`：重新拉取安装脚本并升级指定版本（省略 `--version` 时沿用上次版本）。
- `sudo edgectl start` / `sudo edgectl restart` / `sudo edgectl stop`：通过 systemd 管理 `anyproxy-edge-<NODE_ID>.service`。
- `sudo edgectl info`：输出 Agent 版本、主控 URL、最近通讯时间、配置版本号以及本地服务状态。
- `sudo edgectl uninstall [--purge-config]`：执行官方卸载脚本，额外的 `--purge-config` 会一并删除渲染产物。卸载完成后会自动移除 `edgectl` 本体与状态文件。

## 持久化存储（etcd + PostgreSQL）

生产环境推荐“etcd 下发配置 + PostgreSQL 存管理面”双存储：etcd 仍负责 `configstore.Snapshot/Watch`，而节点/分组/隧道 Agent 等 CRUD 会优先写 PG，再回写等价数据到 etcd 供 Agent 感知，保证 UI/报表层具备事务/查询能力。

1. **使用 Docker Compose 启动依赖**

   ```sh
   docker compose -f deploy/docker-compose.yml up -d postgres etcd
   ```

2. **控制平面接入 etcd + PG**

   ```sh
   go run ./cmd/control-plane \
     -listen :8080 \
     -etcd-endpoints http://127.0.0.1:2379 \
     -etcd-prefix /any-proxy/ \
     -pg-dsn postgres://anyproxy:anyproxy@127.0.0.1:5432/anyproxy?sslmode=disable \
     -seed configs/bootstrap.example.json
   ```

   常用参数：

   - `-etcd-endpoints`：逗号分隔的 etcd 地址，设置后启用强一致配置。
   - `-etcd-username/-etcd-password`：启用 etcd 认证时使用。
   - `-etcd-prefix`：自定义键前缀，便于多环境隔离。
   - `-etcd-timeout/-etcd-dial-timeout`：自定义请求和拨号超时。
   - `-etcd-cert/-etcd-key` / `-etcd-ca`：TLS 证书配置。
   - `-etcd-insecure-skip-verify`：跳过证书校验，仅限测试环境。
   - `-pg-dsn`：PostgreSQL DSN，若设置会自动 AutoMigrate 并启用双存储。
   - `-pg-max-idle/-pg-max-open/-pg-conn-max-lifetime`：可选的连接池参数。

3. **证书生成与轮换**  
   `scripts/etcd-cert-rotate.sh` 提供自动化证书生成、分发与轮换能力：

   ```sh
   chmod +x scripts/etcd-cert-rotate.sh
   scripts/etcd-cert-rotate.sh \
     --inventory configs/etcd-nodes.csv \
     --ca-dir deploy/pki/ca \
     --output-dir deploy/pki/out \
     --client-out configs/etcd-client \
     --restart-cmd "sudo systemctl restart etcd"
   ```

   - `configs/etcd-nodes.csv` 示例列出节点名称、SSH 用户/端口、远端证书目录及 SAN 列表。
   - 首次执行自动生成 CA；每次轮换会在 `deploy/pki/out/<timestamp>/节点名/` 生成新证书，并备份远端旧证书到 `backup-<timestamp>`。
   - 指定 `--client-out` 时，会额外生成控制平面使用的客户端证书 (`client.pem`、`client.crt`、`client.key`)。
   - `--restart-cmd` 可替换为 systemd、容器控制等自定义命令；未指定则仅分发文件。

## REST API

```
GET    /v1/config/snapshot?since=VERSION   # 长轮询获取最新快照
GET    /v1/domains                         # 列出域名路由
POST   /v1/domains                         # 新增/更新域名路由
DELETE /v1/domains/{id}                    # 删除域名路由
GET    /v1/tunnels                         # 列出隧道路由
POST   /v1/tunnels                         # 新增/更新隧道路由
DELETE /v1/tunnels/{id}                    # 删除隧道路由
```

请求体结构可参考 `configs/bootstrap.example.json`，其中时长字段使用 Go duration 语法（如 `5s`、`1m`）。

## 部署注意事项

- 控制平面必须连接 etcd（负责强一致配置）与 PostgreSQL（负责节点/分组等管理元数据）；缺失任意一项都会启动失败。部署多实例时可直接探测 `/healthz`，其中会串行检查 etcd/PG 状态。
- Edge/Tunnel Agent 假设本地已安装 OpenResty/Nginx，并在主配置中 `include` 渲染结果。
- 可结合 Keepalived/VRRP、Anycast 或云负载均衡提供入口高可用及健康探测。
- 建议使用 CI/CD 或 GitOps 流程：配置存 Git -> 流水线调用 Control Plane API -> Agent 自动收敛。

## 开发

```sh
# 获取依赖
go mod tidy

# 代码格式化
go fmt ./...

# 构建自检
go test ./...
```

仓库附带 `configs/bootstrap.example.json`，包含一个示例域名路由与一个 TCP 隧道路由，可用于快速演示与测试。
