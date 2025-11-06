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

### 7.0 环境与资源要求

在批量部署前请确认节点环境满足以下最低要求（推荐使用更高规格以保障性能）：

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Debian 12、Ubuntu 22.04/24.04、RHEL 9、AlmaLinux 9、Rocky Linux 9、CentOS Stream 9、Fedora CoreOS 42、Fedora 40、SLES 15 SP6、openSUSE Leap 15.6、Oracle Linux 9、Amazon Linux 2023 |
| 内核版本 | `>= 5.10.0` |
| GLIBC | `>= 2.34` |
| CPU | `>= 1` vCPU（根据业务建议 2 核以上） |
| 内存 | `>= 2 GB`（生产建议 4 GB 以上） |
| 存储 | `>= 20 GB` 可用磁盘空间 |
| 网络 | 节点需具备入站/出站访问权限；如需限制端口，至少开放入站 80/443，出站 443，其余端口按业务开放 |

### 7.1 一键安装脚本（Linux amd64）

为方便批量部署，可使用仓库提供的脚本输出标准安装命令，在边缘主机直接执行即可完成安装。命令可以重复使用，每次执行都会在目标节点上生成新的节点 ID。

1. **准备静态文件服务**
   将仓库中的 `install/edge-install.sh` 以及 `install/binaries/` 目录暴露为 `https://your-domain.com/install/`。例如 Nginx 配置：

   ```nginx
   location /install/ {
     alias /opt/anyproxy/install/;
     types { }
     default_type application/octet-stream;
     autoindex off;
   }
   ```

   建议在控制平面节点执行 `chmod +x install/edge-install.sh scripts/generate-node-command.sh` 后再挂载目录。

2. **控制平面上生成命令**

   ```bash
   scripts/generate-node-command.sh \
     --type edge \
     --control-plane https://your-domain.com \
     --version v0.1.0
   ```

   脚本会打印一段多行安装命令，并可选显示节点名称、用途、分组等信息。若需要为某个节点指定固定 ID，可额外传入 `--node <ID>`。
   生成的命令类似：

   ```
   curl -fsSL https://your-domain.com/install/edge-install.sh | sudo \
     ANYPROXY_CONTROL_PLANE=https://your-domain.com \
     ANYPROXY_NODE_TYPE=edge \
     ANYPROXY_VERSION=v0.1.0 \
     bash
   ```

3. **在目标节点执行命令**

   复制脚本输出到目标主机执行（需具备 `sudo` 权限）。安装程序会：
   - 自动生成唯一节点 ID 并写入 Systemd 服务；
   - 下载 `edge` 与 `tunnel` agent 二进制（路径形如 `/install/binaries/<版本>/<类型>_linux_amd64.tar.gz`，需提前上传）；
   - 安装到 `/usr/local/bin/anyproxy-<type>`；
   - 生成并启动 Systemd 服务（如 `anyproxy-edge-<节点ID>.service`）；
   - 默认将渲染文件写到 `edge`：`/etc/nginx/conf.d/anyproxy-<节点ID>.conf`，`tunnel`：`/etc/nginx/stream.d/anyproxy-<节点ID>.conf`，可通过 `--output` 覆盖路径。

   如需自定义 `nginx` reload 命令，可在生成命令时通过 `--reload "openresty -s reload"` 透传。

4. **安全提示**  
   由于命令可重复使用，请确保控制平面地址及任意注入的 `ANYPROXY_AGENT_TOKEN` 仅对受信主机可见。如命令泄露，可在控制平面侧旋转访问入口或刷新 Agent 访问令牌。

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
