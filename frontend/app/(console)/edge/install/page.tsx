"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { Monitor, Server, RefreshCw, Copy, Check, Terminal, Shield, Timer, AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { NodeCategory, NodeGroup } from "@/lib/types"
import { fetchNodeGroups } from "@/lib/api"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"

type InstallResponse = {
  command: string
  token: string
  expiresAt: number | null
  expiresAtIso: string | null
  controlPlaneUrl: string
  nodeId: string
  nodeName: string | null
  nodeCategory: string | null
  groupId: string | null
  ttlMinutes: number
  version: string | null
  reloadCmd: string | null
  outputPath: string | null
  streamOutputPath: string | null
  agentToken: string | null
}

const MIN_TTL = 5
const MAX_TTL = 180

const CATEGORY_OPTIONS: { value: NodeCategory; label: string; description: string }[] = [
  { value: "cdn", label: "CDN 节点", description: "用于 HTTP/HTTPS/WebSocket 等应用层流量代理。" },
  { value: "tunnel", label: "内网穿透节点", description: "用于 TCP/UDP 隧道或内网穿透场景。" },
]

const CATEGORY_LABELS: Record<string, string> = {
  cdn: "CDN 节点",
  tunnel: "内网穿透节点",
  waiting: "待分组",
}

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
  const [nodeName, setNodeName] = useState("")
  const [category, setCategory] = useState<NodeCategory>("cdn")
  const [groupId, setGroupId] = useState<string>("")
  const [groups, setGroups] = useState<NodeGroup[]>([])
  const [groupsLoading, setGroupsLoading] = useState(true)
  const [groupsError, setGroupsError] = useState<string | null>(null)
  const [ttlMinutes, setTtlMinutes] = useState(30)
  const [version, setVersion] = useState("")
  const [reloadCmd, setReloadCmd] = useState("")
  const [outputPath, setOutputPath] = useState("")
  const [streamOutputPath, setStreamOutputPath] = useState("")
  const [agentToken, setAgentToken] = useState("")
  const [response, setResponse] = useState<InstallResponse | null>(null)
  const [tick, setTick] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copyState, setCopyState] = useState<"idle" | "copied">("idle")

  useEffect(() => {
    const loadGroups = async () => {
      try {
        setGroupsLoading(true)
        setGroupsError(null)
        const token = await ensureAccessToken()
        if (!token) {
          clearAuthTokens()
          setGroups([])
          return
        }
        const data = await fetchNodeGroups(token)
        setGroups(data)
      } catch (err) {
        console.error("[install] load node groups failed", err)
        setGroupsError(err instanceof Error ? err.message : "加载节点分组失败")
      } finally {
        setGroupsLoading(false)
      }
    }
    void loadGroups()
  }, [])

  const filteredGroups = useMemo(() => groups.filter((group) => group.category === category), [groups, category])

  const resolvedGroupName = useMemo(() => {
    if (!response?.groupId) return null
    const match = groups.find((group) => group.id === response.groupId)
    return match?.name ?? response.groupId
  }, [response?.groupId, groups])

  const resolvedCategoryLabel = useMemo(() => {
    if (!response?.nodeCategory) return null
    const normalized = response.nodeCategory.toLowerCase()
    return CATEGORY_LABELS[normalized] ?? normalized
  }, [response?.nodeCategory])

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
      setLoading(true)
      setError(null)

      try {
        const accessToken = await ensureAccessToken()
        if (!accessToken) {
          setError("登录状态已过期，请重新登录后再生成脚本")
          setLoading(false)
          clearAuthTokens()
          return
        }

        const res = await fetch("/api/install-command", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({
            nodeName: nodeName.trim() || undefined,
            nodeCategory: category,
            groupId: groupId || undefined,
            ttlMinutes: Math.min(Math.max(ttlMinutes, MIN_TTL), MAX_TTL),
            version: version.trim() || undefined,
            reloadCmd: reloadCmd.trim() || undefined,
            outputPath: outputPath.trim() || undefined,
            streamOutputPath: streamOutputPath.trim() || undefined,
            agentToken: agentToken.trim() || undefined,
          }),
          credentials: "include",
        })

        if (!res.ok) {
          if (res.status === 401) {
            setError("登录状态已过期，请重新登录后再生成脚本")
            setLoading(false)
            clearAuthTokens()
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
        if (!streamOutputPath && data.streamOutputPath) {
          setStreamOutputPath(data.streamOutputPath)
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
    [nodeName, category, groupId, ttlMinutes, version, reloadCmd, outputPath, streamOutputPath, agentToken],
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
    } catch {
      setError("复制失败，请手动复制命令")
    }
  }, [response])

  const commandFooter = response
    ? `命令将在 ${timeLeft} 后失效，节点 ID 已自动生成为 ${response.nodeId}。`
    : "命令有效期默认为 30 分钟，系统会自动生成唯一节点 ID。"

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

  const categoryMeta = CATEGORY_OPTIONS.find((item) => item.value === category)

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">部署新边缘</h1>
          <p className="mt-1 text-sm text-muted-foreground">系统会自动生成节点 ID，可选填写名称、用途和分组。</p>
        </div>
        <Button variant="outline" asChild>
          <Link href="/edge">返回节点列表</Link>
        </Button>
      </header>

      <div className="flex-1 space-y-10 overflow-auto px-8 py-10">
        <section>
          <h2 className="text-lg font-semibold text-foreground">选择运行环境</h2>
          <p className="mt-2 text-sm text-muted-foreground">当前提供 Linux x86_64 一键脚本，执行时需具有 sudo 权限。</p>
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
              <h3 className="text-base font-semibold text-foreground">填写节点信息（可选）</h3>
              <p className="text-sm text-muted-foreground">留空则使用系统默认值，后续可在控制台中修改。</p>
            </div>
          </div>

          <div className="ml-12 space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="text-sm font-medium text-foreground">显示名称</label>
                <Input
                  placeholder="例如 华北-生产-A 区"
                  value={nodeName}
                  onChange={(event) => setNodeName(event.target.value)}
                />
              </div>
              <div>
                <label className="text-sm font-medium text-foreground">节点用途</label>
                <Select
                  value={category}
                  onValueChange={(value) => {
                    setCategory(value as NodeCategory)
                    setGroupId("")
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择用途" />
                  </SelectTrigger>
                  <SelectContent>
                    {CATEGORY_OPTIONS.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {categoryMeta ? <p className="mt-1 text-xs text-muted-foreground">{categoryMeta.description}</p> : null}
              </div>
            </div>

            <div>
              <label className="text-sm font-medium text-foreground">归属分组（可选）</label>
              <Select
                value={groupId || "default"}
                onValueChange={(value) => setGroupId(value === "default" ? "" : value)}
                disabled={groupsLoading || !!groupsError}
              >
                <SelectTrigger>
                  <SelectValue placeholder={groupsLoading ? "正在加载…" : "自动归入默认分组"} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="default">自动归入默认分组</SelectItem>
                  {filteredGroups.map((group) => (
                    <SelectItem key={group.id} value={group.id}>
                      {group.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {groupsError ? <p className="mt-1 text-xs text-destructive">{groupsError}</p> : null}
            </div>
          </div>
        </section>

        <section className="space-y-6">
          <div className="flex items-center gap-4">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
              2
            </span>
            <div>
              <h3 className="text-base font-semibold text-foreground">高级参数（可选）</h3>
              <p className="text-sm text-muted-foreground">若需自定义版本、输出目录或 Reload 命令，可在此覆盖。</p>
            </div>
          </div>

          <div className="ml-12 grid gap-4 md:grid-cols-3">
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
              <label className="text-sm font-medium text-foreground">HTTP 配置输出路径（可选）</label>
              <Input
                placeholder="默认写入 /etc/nginx/conf.d/anyproxy-<节点>.conf"
                value={outputPath}
                onChange={(event) => setOutputPath(event.target.value)}
              />
            </div>
            <div>
              <label className="text-sm font-medium text-foreground">隧道配置输出路径（可选）</label>
              <Input
                placeholder="默认写入 /etc/nginx/stream.d/anyproxy-<节点>.conf"
                value={streamOutputPath}
                onChange={(event) => setStreamOutputPath(event.target.value)}
              />
            </div>
            <div className="md:col-span-3">
              <label className="text-sm font-medium text-foreground">Agent 访问令牌（可选）</label>
              <Input
                placeholder="为边缘节点预置控制平面访问令牌，可留空手动下发"
                value={agentToken}
                onChange={(event) => setAgentToken(event.target.value)}
              />
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
                命令有效期有限，请尽快执行。系统将自动携带节点 ID、名称和分组信息。
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
                    生成并复制
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
                placeholder="点击“生成并复制”获取专属安装命令"
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

            {response ? (
              <div className="space-y-1 rounded-md bg-muted/30 p-3 text-xs text-muted-foreground">
                <p>
                  节点 ID：<span className="font-mono text-foreground">{response.nodeId}</span>
                </p>
                {response.nodeName ? (
                  <p>
                    显示名称：<span className="font-mono text-foreground">{response.nodeName}</span>
                  </p>
                ) : null}
                {resolvedCategoryLabel ? (
                  <p>
                    节点用途：<span className="text-foreground">{resolvedCategoryLabel}</span>
                  </p>
                ) : null}
                {resolvedGroupName ? (
                  <p>
                    归属分组：<span className="text-foreground">{resolvedGroupName}</span>
                  </p>
                ) : null}
              </div>
            ) : null}

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
                安装脚本会注册 systemd 服务，稍后可在控制平面中查看节点心跳、IP 与分组信息。
              </p>
            </div>
          </div>

          <ul className="ml-12 list-disc space-y-2 text-sm text-muted-foreground">
            <li>
              脚本会生成 <code>{`anyproxy-edge-${response?.nodeId || "<节点ID>"}.service`}</code>{" "}
              与{" "}
              <code>{`anyproxy-tunnel-${response?.nodeId || "<节点ID>"}.service`}</code>，确保服务状态为 active。
            </li>
            <li>
              如需卸载，可执行{" "}
              <code>{`sudo systemctl disable --now anyproxy-edge-${response?.nodeId || "<节点ID>"}`}</code>{" "}
              与{" "}
              <code>{`sudo systemctl disable --now anyproxy-tunnel-${response?.nodeId || "<节点ID>"}`}</code>{" "}
              并删除对应配置文件。
            </li>
            <li>
              建议为生产节点配置监控：systemd 服务存活、`/var/log/` 中的 agent 日志、OpenResty/Haproxy 状态等指标。
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
