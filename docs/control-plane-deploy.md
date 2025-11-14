# 控制平面部署指南

## 1. 概览
控制平面负责存储与下发域名路由、隧道配置以及节点状态，所有 Edge/Tunnel Agent 都会通过它完成注册与同步。本指南覆盖运行控制平面的两种方式：使用项目自带的 Docker Compose 栈，或独立部署二进制并接入 etcd + PostgreSQL 持久化存储。

## 2. 安装资源与前置条件
- Linux x86_64 主机、Go 1.21+（仅在本地编译时需要）。
- 最低硬件：2 vCPU / 4 GB RAM / 20 GB 磁盘。
- 必须提供 etcd 与 PostgreSQL；控制平面已移除内存模式，缺少任意依赖都会拒绝启动。
- 准备好认证信息：`AUTH_USERNAME`、`AUTH_PASSWORD`、`AUTH_JWT_SECRET`。其余可选 TTL 将在缺省时取 24h/14d。
- **安装脚本与压缩包**：仓库根目录的 `install/edge-install.sh` 会自动通过 Go embed 暴露为 `/install/edge-install.sh`。Agent 二进制压缩包需自行构建：执行
  ```bash
  chmod +x scripts/build-agent-bundles.sh
  scripts/build-agent-bundles.sh v0.1.0
  ```
  即可在 `install/binaries/v0.1.0/` 下生成 `edge_linux_amd64.tar.gz`、`tunnel_linux_amd64.tar.gz` 及对应 `.sha256`。如需提供滚动“最新”版本，可以在 `install/binaries` 内创建软链接 `ln -sfn v0.1.0 latest`。这些文件会通过控制平面的 `/install/binaries/<版本>/...` 路径提供给安装脚本下载。
  边缘节点默认只部署 `edge-agent` 并写入 `/etc/nginx/conf.d/*.conf` 与 `/etc/haproxy/haproxy.cfg`；内网节点如需运行 `tunnel-agent`，将 `ANYPROXY_NODE_TYPE` 设为 `tunnel` 即可。

## 3. 关键配置
控制平面通过环境变量驱动：

| 变量 | 说明 |
| --- | --- |
| `CONTROL_PLANE_LISTEN` | 监听地址，默认 `:8080`。 |
| `ETCD_ENDPOINTS` | 逗号分隔的 etcd 地址，设置后启用持久化。 |
| `ETCD_PREFIX` | etcd 键前缀，默认 `/any-proxy/`。 |
| `ETCD_CERT/ETCD_KEY/ETCD_CA` | etcd mTLS 所需证书。 |
| `PG_DSN` | PostgreSQL DSN，例如 `postgres://anyproxy:anyproxy@postgres:5432/anyproxy?sslmode=disable`。 |
| `PG_MAX_IDLE/PG_MAX_OPEN/PG_CONN_MAX_LIFETIME` | Postgres 连接池参数，可选。 |
| `AUTH_USERNAME/PASSWORD` | 控制面登录账号。 |
| `AUTH_JWT_SECRET` | JWT 签名；需 32+ 字节。 |
| `INSTALL_ASSETS_DIR` | （可选）指定本地 `install/` 目录，若为空则使用内置脚本并忽略二进制资源。 |

种子配置：可将 `configs/bootstrap.example.json` 复制定制，启动时传 `-seed /configs/bootstrap.json` 让控制平面自动落库。

## 4. Docker Compose 部署
1. 复制 `deploy/.env.example`（如有）并填入上述变量，尤其是 `AUTH_*`、`ETCD_*` 与 `PG_*`。确保 `install/binaries/<版本>/` 目录存在（可用 `scripts/build-agent-bundles.sh v0.1.0` 生成）。PostgreSQL 会将数据写入 `deploy/pg-data/`（已在 `.gitignore` 中忽略），请确认该目录在宿主机上持久化或绑定到合适的磁盘。
2. 进入 `deploy/`，执行：
   ```bash
   docker compose up -d --build
   ```
   该栈包含 PostgreSQL、etcd、control-plane、Next.js 前端与 gateway（Nginx）。`control-plane` 容器会将 `../install` 挂载为 `/app/install`，自动向外暴露 `/install/edge-install.sh`，并在启动时执行 PG AutoMigrate 与 etcd/PG 双写。
3. 验证：
   ```bash
   curl http://<网关>/gateway/healthz        # Nginx 探活
   curl http://<控制面>/healthz              # 控制平面探活
   curl http://<控制面>/install/edge-install.sh | head
   ```
4. 登录前端 `http://<网关>/`，使用 `AUTH_USERNAME/PASSWORD` 获取 token 后即可管理域名/隧道。

## 5. 独立二进制部署
1. 构建：
   ```bash
   go build -o bin/control-plane ./cmd/control-plane
   ```
2. 准备配置文件：
   ```bash
   cat > /etc/anyproxy/control-plane.env <<'EOF'
   CONTROL_PLANE_LISTEN=:8080
   ETCD_ENDPOINTS=http://127.0.0.1:2379
   AUTH_USERNAME=admin
   AUTH_PASSWORD=changeme
   AUTH_JWT_SECRET=$(openssl rand -hex 32)
   INSTALL_ASSETS_DIR=/opt/anyproxy/install
   EOF
   ```
3. 启动：
   ```bash
   source /etc/anyproxy/control-plane.env
   ./bin/control-plane \
     -listen "${CONTROL_PLANE_LISTEN}" \
     -etcd-endpoints "${ETCD_ENDPOINTS}" \
     -etcd-prefix /any-proxy/ \
     -pg-dsn "${PG_DSN:-postgres://anyproxy:anyproxy@127.0.0.1:5432/anyproxy?sslmode=disable}" \
     -seed /opt/anyproxy/configs/bootstrap.json
   ```
4. 建议使用 systemd 守护，`ExecStart` 与上面命令一致，并将 `Restart=always`、`LimitNOFILE=65535` 等参数写入。

## 6. 持久化与 TLS
- 若 etcd 开启双向 TLS，将证书复制到容器或宿主机，并通过环境变量指向：  
  `ETCD_CERT=/app/pki/client.crt`、`ETCD_KEY=/app/pki/client.key`、`ETCD_CA=/app/pki/ca.crt`。
- PostgreSQL DSN 推荐包含 `sslmode=require/verify-full` 并开启对应证书，控制面仅需要读写节点/分组等管理表，AutoMigrate 会自动创建/升级 schema。
- 控制平面本身对外暴露 HTTP，可通过 gateway/Ingress 加 TLS，或在前方部署反向代理（如 Nginx、Traefik）并将 `/v1/*`、`/auth/*`、`/install/*` 转发到控制平面。

## 7. 运行检查与排障
- `GET /healthz`：检查控制平面与 etcd 连接；etcd 异常时返回 500。
- `docker compose logs control-plane`（或 systemd journal）排查认证失败、etcd 超时等问题。
- 如果 `/install/edge-install.sh` 404，确认 `INSTALL_ASSETS_DIR` 是否包含脚本及 `binaries` 子目录；或检查容器挂载。
- 若 Agent 无法注册，查看 `/v1/nodes/register` 日志并确认 `AUTH_*`、token 以及网络连通性。

## 8. 节点安装命令示例
在控制平面节点上可通过列目录找到最新的二进制版本，再将信息复制到安装命令中：
```bash
VERSION=$(ls install/binaries | sort -Vr | head -n1)   # 例如 v0.1.0 或 latest
curl -fsSL https://your-domain.com/install/edge-install.sh | sudo \
  ANYPROXY_CONTROL_PLANE=https://your-domain.com \
  ANYPROXY_NODE_TYPE=edge \
  ANYPROXY_VERSION="${VERSION}" \
  bash
```
若使用 `generate-node-command.sh` 输出的多行命令，也务必将 `--version`/`ANYPROXY_VERSION` 与实际存在的目录一致，否则安装脚本会在下载阶段报 404。

完成上述步骤后，控制平面即可接受前端与 Agent 请求，并对外提供安装脚本与配置分发能力。结合 `scripts/generate-node-command.sh` 可以快速向边缘节点分发注册命令。***
