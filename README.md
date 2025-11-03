# any-proxy

any-proxy 是一个面向内部 CDN / 内网穿透场景的控制平面与节点代理套件。控制平面使用 Go 编写，边缘节点采用 Nginx/OpenResty，通过分布式配置同步、长轮询和模板渲染实现高可用域名转发与 TCP 隧道暴露。

## 组件简介

- **Control Plane (`cmd/control-plane`)**：维护域名/隧道路由，提供 `/v1/config/...` REST 接口，支持内存或 etcd 存储，并具备长轮询能力。
- **Edge Agent (`cmd/edge-agent`)**：监听与自身节点匹配的 HTTP/S 路由，渲染 OpenResty `nginx.conf` 并执行可选的 reload 命令。
- **Tunnel Agent (`cmd/tunnel-agent`)**：监听 TCP/UDP 隧道配置，渲染 `stream.conf` 并重载 OpenResty，实现内网端口穿透。
- **Templates (`pkg/templates`)**：默认的 HTTP / Stream 模板，可通过 `-template` 参数覆盖以注入自定义指令。

## 快速开始

1. **可选：加载示例配置**

   ```sh
   go run ./cmd/control-plane -seed configs/bootstrap.example.json
   ```

2. **运行控制平面（内存模式）**

   ```sh
   go run ./cmd/control-plane -listen :8080
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
     -output ./deploy/generated/stream.conf \
     -reload "openresty -s reload" \
     -dry-run
   ```

默认仅在版本号变化时重新渲染模板。生产环境请移除 `-dry-run`，让 reload 命令（如 `openresty -s reload` 或自定义脚本）实际执行。

## 持久化存储（etcd）

1. **使用 Docker Compose 启动 etcd**

   ```sh
   docker compose -f deploy/docker-compose.yml up -d etcd
   ```

2. **控制平面接入 etcd**

   ```sh
   go run ./cmd/control-plane \
     -listen :8080 \
     -etcd-endpoints http://127.0.0.1:2379 \
     -etcd-prefix /any-proxy/ \
     -seed configs/bootstrap.example.json
   ```

   常用参数：

   - `-etcd-endpoints`：逗号分隔的 etcd 地址，设置后启用持久化。
   - `-etcd-username/-etcd-password`：启用 etcd 认证时使用。
   - `-etcd-prefix`：自定义键前缀，便于多环境隔离。
   - `-etcd-timeout/-etcd-dial-timeout`：自定义请求和拨号超时。
   - `-etcd-cert/-etcd-key`：客户端证书/私钥（支持双向 TLS）。
   - `-etcd-ca`：指定 CA 证书束，用于校验私有/自签证书。
   - `-etcd-insecure-skip-verify`：跳过证书校验，仅限测试环境。

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

- 控制平面可多实例部署，结合 LB + etcd 保障一致性；内存模式下重启会清空配置。部署 LB 时可直接探测 `/healthz`，etcd 模式会附加后端连通性检查。
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
