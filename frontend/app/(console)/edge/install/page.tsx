"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { Monitor, Server, RefreshCw, Copy, Check, Terminal, Shield, Timer, AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { Badge } from "@/components/ui/badge"

type InstallResponse = {
  command: string
  token: string
  expiresAt: number | null
  expiresAtIso: string | null
  controlPlaneUrl: string
  nodeType: string
  nodeId: string
  ttlMinutes: number
  version: string | null
  reloadCmd: string | null
  outputPath: string | null
  agentToken: string | null
}

const MIN_TTL = 5
const MAX_TTL = 180

function formatRemaining(expiryIso: string | null): string {
  if (!expiryIso) return "未知"
  const expiresAt = new Date(expiryIso).getTime()
  const diff = expiresAt - Date.now()
  if (Number.isNaN(expiresAt) || diff <= 0) {
    return "已过期"
  }
  const minutes = Math.floor(diff / 60000)
  const seconds = Math.floor((diff % 60000) / 1000)
  const mm = minutes.toString().padStart(2, "0")
  const ss = seconds.toString().padStart(2, "0")
  return `${mm}分${ss}秒`
}

export default function EdgeInstallPage() {
  const [nodeType, setNodeType] = useState<"edge" | "tunnel">("edge")
  const [nodeId, setNodeId] = useState("")
  const [ttlMinutes, setTtlMinutes] = useState(30)
  const [version, setVersion] = useState("")
  const [reloadCmd, setReloadCmd] = useState("")
  const [outputPath, setOutputPath] = useState("")
  const [agentToken, setAgentToken] = useState("")
  const [response, setResponse] = useState<InstallResponse | null>(null)
  const [tick, setTick] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copyState, setCopyState] = useState<"idle" | "copied">("idle")

  const timeLeft = useMemo(
    () => formatRemaining(response?.expiresAtIso ?? null),
    [response?.expiresAtIso, tick],
  )

  useEffect(() => {
    if (copyState !== "copied") return
    const timer = setTimeout(() => setCopyState("idle"), 2200)
    return () => clearTimeout(timer)
  }, [copyState])

  useEffect(() => {
    if (!response?.expiresAtIso) return
    setTick(0)
    const interval = setInterval(() => {
      setTick((value) => value + 1)
    }, 1000)
    return () => clearInterval(interval)
  }, [response?.expiresAtIso])

  const generateCommand = useCallback(
    async (copyAfter = false) => {
      if (!nodeId.trim()) {
        setError("请先填写节点 ID")
        return
      }

      setLoading(true)
      setError(null)

      try {
        const res = await fetch("/api/install-command", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            nodeType,
            nodeId: nodeId.trim(),
            ttlMinutes: Math.min(Math.max(ttlMinutes, MIN_TTL), MAX_TTL),
            version: version.trim() || undefined,
            reloadCmd: reloadCmd.trim() || undefined,
            outputPath: outputPath.trim() || undefined,
            agentToken: agentToken.trim() || undefined,
          }),
        })

        if (!res.ok) {
          if (res.status === 401) {
            setError("登录状态已过期，请重新登录后再生成脚本")
            setLoading(false)
            return
          }
          const detail = await res.json().catch(() => ({}))
          throw new Error(detail?.error || "生成安装命令失败")
        }

        const data: InstallResponse = await res.json()
        setResponse(data)
        if (!agentToken && data.agentToken) {
          setAgentToken(data.agentToken)
        }
        setTick(0)

        if (copyAfter && data.command) {
          if (typeof navigator === "undefined" || !navigator.clipboard) {
            setError("当前环境不支持自动复制，请手动复制命令")
            setCopyState("idle")
          } else {
            await navigator.clipboard.writeText(data.command)
            setCopyState("copied")
          }
        } else {
          setCopyState("idle")
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "生成安装命令失败")
      } finally {
        setLoading(false)
      }
    },
    [nodeType, nodeId, ttlMinutes, version, reloadCmd, outputPath],
  )

  const handleCopy = useCallback(async () => {
    if (!response?.command) return
    if (typeof navigator === "undefined" || !navigator.clipboard) {
      setError("当前环境不支持自动复制，请手动复制命令")
      return
    }
    try {
      await navigator.clipboard.writeText(response.command)
      setCopyState("copied")
    } catch (err) {
      setError("复制失败，请手动复制命令")
    }
  }, [response])

  const commandFooter = response
    ? `该命令由 ${response.controlPlaneUrl} 生成，token 将在 ${timeLeft} 后失效`
    : "生成后请在有效期内执行，默认有效期 30 分钟"

  const linuxCard = (
    <div className="grid w-56 place-items-center rounded-lg border border-border bg-background/60 p-6 text-center shadow-sm">
      <Monitor className="h-10 w-10 text-primary" />
      <div className="mt-3 space-y-1">
        <p className="text-base font-semibold text-foreground">Linux</p>
        <p className="text-xs text-muted-foreground">支持 x86_64 架构，需 sudo 权限</p>
      </div>
    </div>
  )

  const placeholderCard = (
    <div className="grid w-56 place-items-center rounded-lg border border-dashed border-border/70 bg-muted/30 p-6 text-center text-muted-foreground">
      <Server className="h-10 w-10" />
      <div className="mt-3 space-y-1">
        <p className="text-base font-semibold">更多平台</p>
        <p className="text-xs">敬请期待</p>
      </div>
    </div>
  )

  const canCopy = typeof navigator !== "undefined" && !!navigator.clipboard

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">部署新边缘</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            生成一次性安装脚本，在 Linux 节点上执行即可完成 Edge/Tunnel Agent 部署。
          </p>
        </div>
        <Button variant="outline" asChild>
          <Link href="/edge">返回边缘列表</Link>
        </Button>
      </header>

      <div className="flex-1 space-y-10 overflow-auto px-8 py-10">
        <section>
          <h2 className="text-lg font-semibold text-foreground">选择运行环境</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            当前提供 Linux x86_64 一键脚本，确认实例具备对控制平面的网络连通性。
          </p>
          <div className="mt-6 flex flex-wrap gap-6">
            {linuxCard}
            {placeholderCard}
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-4">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
              1
            </span>
            <div>
              <h3 className="text-base font-semibold text-foreground">准备部署</h3>
              <p className="text-sm text-muted-foreground">
                确保节点具备 sudo 权限，开放 80/443 出站访问，节点与控制平面网络互通。
              </p>
            </div>
          </div>
          <ul className="ml-12 list-disc space-y-2 text-sm text-muted-foreground">
            <li>推荐使用 Debian 12、Ubuntu 22.04、CentOS Stream 9、RockyLinux 9 等发行版。</li>
            <li>内核版本建议 ≥ 5.10，GLIBC ≥ 2.34，至少 2 GB 内存与 20 GB 剩余磁盘空间。</li>
            <li>节点需允许访问控制平面暴露的 8080/443 等端口，保证配置可拉取。</li>
          </ul>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-4">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
              2
            </span>
            <div>
              <h3 className="text-base font-semibold text-foreground">填写节点信息</h3>
              <p className="text-sm text-muted-foreground">根据业务场景选择 Agent 类型，并指定唯一的节点 ID。</p>
            </div>
          </div>

          <div className="ml-12 space-y-4">
            <ToggleGroup
              type="single"
              value={nodeType}
              onValueChange={(value) => {
                if (value === "edge" || value === "tunnel") {
                  setNodeType(value)
                  setResponse(null)
                  setCopyState("idle")
                }
              }}
              className="bg-muted/30"
            >
              <ToggleGroupItem value="edge">HTTP/S 边缘</ToggleGroupItem>
              <ToggleGroupItem value="tunnel">TCP/UDP 隧道</ToggleGroupItem>
            </ToggleGroup>

            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="text-sm font-medium text-foreground">节点 ID</label>
                <Input
                  placeholder="例如 edge-shanghai-01"
                  value={nodeId}
                  onChange={(event) => setNodeId(event.target.value)}
                />
              </div>

              <div>
                <label className="text-sm font-medium text-foreground">令牌有效期（分钟）</label>
                <Input
                  type="number"
                  min={MIN_TTL}
                  max={MAX_TTL}
                  value={ttlMinutes}
                  onChange={(event) => setTtlMinutes(Number(event.target.value) || 30)}
                />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div>
                <label className="text-sm font-medium text-foreground">Agent 版本（可选）</label>
                <Input
                  placeholder="默认 latest"
                  value={version}
                  onChange={(event) => setVersion(event.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium text-foreground">Reload 命令（可选）</label>
                <Input
                  placeholder='默认 "nginx -s reload"'
                  value={reloadCmd}
                  onChange={(event) => setReloadCmd(event.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium text-foreground">配置输出路径（可选）</label>
                <Input
                  placeholder="默认依类型写入 conf.d / stream.d"
                  value={outputPath}
                  onChange={(event) => setOutputPath(event.target.value)}
                />
              </div>
              <div className="md:col-span-3">
                <label className="text-sm font-medium text-foreground">Agent 访问令牌（可选）</label>
                <Input
                  placeholder="为边缘节点填入控制平面访问令牌，可留空手动补充"
                  value={agentToken}
                  onChange={(event) => setAgentToken(event.target.value)}
                />
              </div>
            </div>
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-4">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
              3
            </span>
            <div>
              <h3 className="text-base font-semibold text-foreground">生成安装命令</h3>
              <p className="text-sm text-muted-foreground">
                命令有效期有限，请尽快在目标主机执行。每条命令仅建议使用一次。
              </p>
            </div>
          </div>

          <div className="ml-12 space-y-4">
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => generateCommand(true)} disabled={loading}>
                {loading ? (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                    正在生成…
                  </>
                ) : (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4" />
                    重新生成并复制
                  </>
                )}
              </Button>
              <Button variant="outline" onClick={handleCopy} disabled={!response?.command || !canCopy}>
                {copyState === "copied" ? (
                  <>
                    <Check className="mr-2 h-4 w-4" />
                    已复制
                  </>
                ) : (
                  <>
                    <Copy className="mr-2 h-4 w-4" />
                    复制命令
                  </>
                )}
              </Button>
            </div>

            <div className="relative">
              <Textarea
                className="min-h-32 bg-muted/40 font-mono text-sm"
                value={response?.command ?? ""}
                readOnly
                placeholder="点击“重新生成并复制”获取专属安装命令"
              />
              {response?.expiresAtIso && (
                <div className="absolute right-3 top-3">
                  <Badge variant="secondary" className="flex items-center gap-1">
                    <Timer className="h-3 w-3" />
                    {timeLeft}
                  </Badge>
                </div>
              )}
            </div>

            <p className="flex items-start gap-2 text-sm text-muted-foreground">
              <Terminal className="mt-0.5 h-4 w-4 shrink-0 text-foreground/70" />
              {commandFooter}
            </p>

            {error && (
              <p className="flex items-center gap-2 text-sm text-destructive">
                <AlertCircle className="h-4 w-4" />
                {error}
              </p>
            )}
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-4">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
              4
            </span>
            <div>
              <h3 className="text-base font-semibold text-foreground">运行后检查</h3>
              <p className="text-sm text-muted-foreground">
                安装脚本会注册 systemd 服务，稍候可在控制平面中看到新节点的心跳与配置版本。
              </p>
            </div>
          </div>

          <ul className="ml-12 list-disc space-y-2 text-sm text-muted-foreground">
            <li>
              脚本会生成 <code>{`anyproxy-{edge|tunnel}-{节点ID}.service`}</code>，确保服务状态为 active。
            </li>
            <li>
              如需卸载，可执行{" "}
              <code>{`sudo systemctl disable --now anyproxy-{edge|tunnel}-{节点ID}`}</code> 并删除对应配置文件。
            </li>
            <li>
              建议为生产节点配置监控：systemd 服务存活、`/var/log/` 中的 agent 日志、Nginx worker 状态等指标。
            </li>
          </ul>
        </section>

        <section className="space-y-4 rounded-lg border border-border bg-muted/20 p-6">
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-primary" />
            <div>
              <h3 className="text-base font-semibold text-foreground">安全提醒</h3>
              <p className="text-sm text-muted-foreground">
                令牌超时后会自动失效，可在主控节点定期清理 `/opt/anyproxy/install/tokens` 目录，避免堆积。
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}
