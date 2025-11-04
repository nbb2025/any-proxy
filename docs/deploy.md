# 部署指南

本文档说明如何在 Docker/Compose 环境下部署 any-proxy，包括控制平面、etcd 存储以及前端控制台。  
如果仅需本地开发或快速体验，可直接使用默认示例；若用于生产，请重点关注 TLS、持久化以及监控部分。

---

## 1. 前置要求

1. **操作系统**：Linux / macOS / Windows（需启用 WSL2 或 Docker Desktop）。
2. **工具链**：
   - Docker Engine ≥ 24.x
   - Docker Compose Plugin ≥ v2.20（`docker compose version`）
   - Git（便于拉取代码）
3. **可选**：在有 mTLS 需求时，服务器需具备 SSH 访问能力以便证书分发脚本使用。

---

## 2. 拉取代码

```bash
git clone https://github.com/nbb2025/any-proxy.git
cd any-proxy
```

后续命令默认在仓库根目录执行。

---

## 3. (可选) 生成 & 分发 etcd 证书

如要开启 etcd mTLS，可利用仓库自带脚本：

1. 编辑 `configs/etcd-nodes.csv`，填入 etcd 节点的 SSH 参数、证书存放目录、SAN 列表等信息。
2. 执行脚本：

   ```bash
   chmod +x scripts/etcd-cert-rotate.sh
   scripts/etcd-cert-rotate.sh \
     --inventory configs/etcd-nodes.csv \
     --ca-dir deploy/pki/ca \
     --output-dir deploy/pki/out \
     --client-out deploy/pki/client \
     --restart-cmd "sudo systemctl restart etcd"
   ```

   - 首次执行会生成 CA 及各节点证书，并备份原有证书。
   - `deploy/pki/client/` 目录下会生成控制平面使用的 `client.crt` / `client.key` / `ca.crt`。
   - 若暂不启用 TLS，可跳过该步骤。

---

## 4. 配置环境变量

Compose 栈读取 `deploy/.env` 中的变量。可基于示例复制一份：

```bash
cp deploy/.env.example deploy/.env
```

关键配置说明：

| 变量 | 含义 | 默认值 |
| --- | --- | --- |
| `CONTROL_PLANE_LISTEN` | 控制平面容器内部监听地址 | `:8080` |
| `CONTROL_PLANE_PORT` | 宿主机暴露的控制平面端口 | `8080` |
| `ETCD_ENDPOINTS` | 控制平面访问 etcd 的地址 | `http://etcd:2379` |
| `ETCD_PREFIX` | 配置前缀，方便多环境隔离 | `/any-proxy/` |
| `CONTROL_PLANE_SEED` | 可选，启动时导入的 seed JSON | 为空 |
| `ETCD_CERT/KEY/CA` | 可选，etcd 客户端证书路径（容器内路径） | 为空 |
| `ETCD_INSECURE_SKIP_VERIFY` | 设为 `true` 可跳过证书校验（仅用于测试） | 空 |
| `FRONTEND_PORT` | 前端暴露端口 | `3000` |
| `FRONTEND_CONTROL_PLANE_URL` | 前端访问控制平面使用的 URL | `http://localhost:8080` |

如开启 mTLS，可在 `.env` 中填入：

```dotenv
CONTROL_PLANE_SEED=/configs/bootstrap.example.json
ETCD_CERT=/app/pki/client/client.crt
ETCD_KEY=/app/pki/client/client.key
ETCD_CA=/app/pki/client/ca.crt
```

> ⚠️ 以上路径均为容器内路径，证书目录会通过 `deploy/docker-compose.yml` 中的 `./deploy/pki:/app/pki:ro` 映射提供。

---

## 5. 启动 Compose 栈

```bash
cd deploy
docker compose up -d --build
```

Compose 服务说明：

| 服务 | 描述 | 默认端口 |
| --- | --- | --- |
| `etcd` | 配置存储（单节点演示版） | 2379 |
| `control-plane` | Go 控制平面 API | 8080 |
| `frontend` | Next.js 控制台 | 3000 |

查看运行状态：

```bash
docker compose ps
```

访问：
- 控制平面健康检查: `http://localhost:8080/healthz`
- REST 接口示例: `http://localhost:8080/v1/config/snapshot`
- 前端控制台: `http://localhost:3000`

停用：

```bash
docker compose down
```

保留数据卷（etcd 数据）以便下次重用。

---

## 6. 验证配置同步

1. `curl http://localhost:8080/v1/domains` 观察返回值。
2. 前端仪表盘应同步展示域名/隧道/节点信息。
3. 若需要导入种子配置，可将 JSON 放在 `configs/` 下并设置 `CONTROL_PLANE_SEED=/configs/xxx.json`。

---

## 7. 启动边缘 / 隧道 Agent

在需要执行代理的节点（带有 OpenResty/Nginx）上：

```bash
./edge-agent \
  -control-plane http://<control-plane-host>:8080 \
  -node-id edge-a \
  -output /etc/nginx/conf.d/edge.conf \
  -reload "nginx -s reload"

./tunnel-agent \
  -control-plane http://<control-plane-host>:8080 \
  -node-id tunnel-a \
  -output /etc/nginx/stream.d/tunnel.conf \
  -reload "nginx -s reload"
```

确保 OpenResty 主配置包含相应 `include`，并通过 `systemd` 等方式守护进程。

---

### 7.1 一键安装脚本（Linux amd64）

为方便批量部署，可使用仓库新增的脚本生成一次性命令，在边缘主机直接执行即可完成安装。

1. **准备静态文件服务**  
   将仓库中的 `install/agent.sh` 暴露为 `https://anyproxy.weekeasy.com/install/agent.sh`，并把 `scripts/generate-node-command.sh` 生成的 token JSON（默认存放在 `/opt/anyproxy/install/tokens/`）一起通过 Web 服务器提供。例如 Nginx 配置示例：

   ```nginx
   location /install/ {
     alias /opt/anyproxy/install/;
     types { }
     default_type application/octet-stream;
     autoindex off;
   }
   ```

   建议在控制平面节点上执行 `chmod +x install/agent.sh scripts/generate-node-command.sh` 后再挂载目录。

2. **控制平面上生成命令**

   ```bash
   scripts/generate-node-command.sh \
     --type edge \
     --node edge-shanghai-01 \
     --control-plane https://anyproxy.weekeasy.com \
     --version v0.1.0 \
     --ttl-min 60
   ```

   脚本会输出一次性 token，并生成一段多行安装命令。JSON token 默认写入 `/opt/anyproxy/install/tokens/<token>.json`，有效期可通过 `--ttl-min`（分钟）调整。
   命令形如：

   ```
   curl -fsSL https://anyproxy.weekeasy.com/install/agent.sh | sudo \
     ANYPROXY_CONTROL_PLANE=https://anyproxy.weekeasy.com \
     ANYPROXY_NODE_TYPE=edge \
     ANYPROXY_NODE_ID=edge-shanghai-01 \
     ANYPROXY_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
     ANYPROXY_VERSION=v0.1.0 \
     bash
   ```

3. **在目标节点执行命令**

   复制粘贴脚本打印的命令到目标主机（需具备 `sudo` 权限，命令通过环境变量传入 token/节点信息），安装程序会：
   - 校验 token 是否仍然有效；
   - 下载 `edge` 或 `tunnel` agent 二进制（路径形如 `/install/binaries/<版本>/<类型>_linux_amd64.tar.gz`，需提前上传）；
   - 写入 `/usr/local/bin/anyproxy-<type>`；
   - 生成 Systemd 服务文件（如 `anyproxy-edge-edge-shanghai-01.service`）并立即启动；
   - 默认把渲染文件写到 `edge`：`/etc/nginx/conf.d/anyproxy-<node>.conf`，`tunnel`：`/etc/nginx/stream.d/anyproxy-<node>.conf`，可通过 `--output` 覆盖。

   如果需要自定义 `nginx` reload 命令，可在控制端生成 token 时附加 `--reload "openresty -s reload"`，脚本会把参数透传到安装命令中。

4. **Token 清理与安全**  
   token 一次有效，过期后安装脚本会拒绝执行。可结合 `cron` 或 Systemd Timer 定期清理 `/opt/anyproxy/install/tokens/` 中早于当前时间的 JSON 文件，避免目录无限增长。

---

## 8. 生产部署建议

1. **etcd 集群**  
   - 使用 3~5 节点、不同可用区部署，并开启 mTLS、鉴权、快照备份。  
   - 定期执行 `etcdctl snapshot save`、`compact`/`defrag` 操作。

2. **控制平面**  
   - 至少部署 2 副本，通过负载均衡器（或 Ingress）对外暴露 `/healthz`。  
   - 搭配日志采集、Prometheus 指标与告警体系。

3. **边缘节点**  
   - 使用 Keepalived/VRRP、Anycast 或云 SLB 实现高可用；  
   - 结合 `scripts/etcd-cert-rotate.sh` 定期轮换证书，避免人工维护。

4. **CI/CD**  
   - 将配置写入 Git 仓库，通过流水线调用控制平面 API（或 `go run ./cmd/control-plane -seed`）自动下发；  
   - 前端 & 控制平面镜像可推送至企业镜像仓库，按版本发布。

---

## 9. 常见问题

| 问题 | 可能原因 | 解决方案 |
| --- | --- | --- |
| `/v1/config/snapshot` 返回 500 | etcd 未就绪或凭据错误 | 检查 compose 日志，验证 env 中的证书/地址 |
| 前端无法加载数据 | `NEXT_PUBLIC_CONTROL_PLANE_URL` 未指向暴露地址 | 修改 `deploy/.env` 并重新 `docker compose up -d --build` |
| Agent 收不到更新 | 控制平面未配置 seed / API 未写入 | 调用 `/v1/domains`、`/v1/tunnels` 接口创建路由 |
| etcd 认证失败 | 未挂载证书或权限错误 | 确认 `deploy/pki` 中的证书与 env 填写一致，权限 600 |

---

完成上述步骤后，即可获得一个具备控制平面、前端可视化，以及可扩展到边缘节点的 any-proxy 部署。欢迎结合自身环境进一步扩展监控、审计、自动化运维流程。祝部署顺利！
