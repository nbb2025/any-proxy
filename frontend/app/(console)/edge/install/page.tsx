"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { Monitor, Server, RefreshCw, Copy, Check, Terminal, Shield, AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { NodeCategory, NodeGroup } from "@/lib/types"
import { fetchNodeGroups } from "@/lib/api"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"

type InstallResponse = {
  command: string
  controlPlaneUrl: string
  nodeType: string
  nodeId: string | null
  nodeName: string | null
  nodeCategory: string | null
  groupId: string | null
  agentToken: string | null
  autoGeneratesNodeId: boolean
}

const SUPPORTED_OS_GROUPS: { title: string; entries: string[] }[] = [
  { title: "Debian / Ubuntu", entries: ["Debian 12 (bookworm)", "Ubuntu 22.04", "Ubuntu 24.04"] },
  { title: "Red Hat 系", entries: ["Red Hat Enterprise Linux 9", "AlmaLinux 9", "Rocky Linux 9", "CentOS Stream 9", "Oracle Linux 9"] },
  { title: "Fedora / CoreOS", entries: ["Fedora CoreOS 42", "Fedora 40"] },
  { title: "SUSE 家族", entries: ["SLES 15 SP6", "openSUSE Leap 15.6"] },
  { title: "Amazon Linux", entries: ["Amazon Linux 2023"] },
]

const RESOURCE_REQUIREMENTS: { label: string; value: string }[] = [
  { label: "Linux 内核版本", value: ">= 5.10.0" },
  { label: "GLIBC", value: ">= 2.34" },
  { label: "CPU 核心数", value: ">= 1" },
  { label: "内存空间", value: ">= 2 GB" },
  { label: "存储空间", value: ">= 20 GB" },
]

const NETWORK_REQUIREMENT =
  "边缘节点需具备入站/出站网络访问能力。如需限制端口，至少开放入站 80 与 443，出站 443，其余端口按照业务需求配置。"

const CATEGORY_OPTIONS: { value: NodeCategory; label: string; description: string }[] = [
  { value: "cdn", label: "CDN 节点", description: "用于 HTTP/HTTPS/WebSocket 等应用层流量代理。" },
  { value: "tunnel", label: "内网穿透节点", description: "用于 TCP/UDP 隧道或内网穿透场景。" },
]

const CATEGORY_LABELS: Record<string, string> = {
  cdn: "CDN 节点",
  tunnel: "内网穿透节点",
  waiting: "待分组",
}

export default function EdgeInstallPage() {
  const [nodeName, setNodeName] = useState("")
  const [category, setCategory] = useState<NodeCategory>("cdn")
  const [groupId, setGroupId] = useState<string>("")
  const [groups, setGroups] = useState<NodeGroup[]>([])
  const [groupsLoading, setGroupsLoading] = useState(true)
  const [groupsError, setGroupsError] = useState<string | null>(null)
  const [agentToken, setAgentToken] = useState("")
  const [response, setResponse] = useState<InstallResponse | null>(null)
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

  useEffect(() => {
    if (copyState !== "copied") return
    const timer = setTimeout(() => setCopyState("idle"), 2200)
    return () => clearTimeout(timer)
  }, [copyState])

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
    [nodeName, category, groupId, agentToken],
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
    ? response.autoGeneratesNodeId
      ? "执行命令后，节点会在首次注册时自动生成唯一 ID。"
      : `节点 ID 已锁定为 ${response.nodeId ?? "（未返回）"}。`
    : "执行命令后，节点会在首次注册时自动生成唯一 ID。"

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
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-foreground">运行环境要求</h2>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            <div className="rounded-lg border border-border bg-muted/30 p-4">
              <h3 className="text-sm font-semibold text-foreground">通过验证的发行版</h3>
              <ul className="mt-3 space-y-2 text-sm text-muted-foreground">
                {SUPPORTED_OS_GROUPS.map((group) => (
                  <li key={group.title}>
                    <p className="font-medium text-foreground">{group.title}</p>
                    <p>{group.entries.join("，")}</p>
                  </li>
                ))}
              </ul>
            </div>
            <div className="rounded-lg border border-border bg-muted/30 p-4">
              <h3 className="text-sm font-semibold text-foreground">资源配置建议</h3>
              <dl className="mt-3 space-y-2 text-sm text-muted-foreground">
                {RESOURCE_REQUIREMENTS.map((item) => (
                  <div key={item.label} className="flex justify-between gap-2">
                    <dt className="font-medium text-foreground">{item.label}</dt>
                    <dd>{item.value}</dd>
                  </div>
                ))}
              </dl>
            </div>
            <div className="rounded-lg border border-border bg-muted/30 p-4">
              <h3 className="text-sm font-semibold text-foreground">网络连通性</h3>
              <p className="mt-3 text-sm text-muted-foreground">{NETWORK_REQUIREMENT}</p>
            </div>
          </div>
        </section>

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
              <h3 className="text-base font-semibold text-foreground">生成安装命令</h3>
              <p className="text-sm text-muted-foreground">
                命令会包含控制平面地址与可选信息，节点 ID 将在安装脚本运行时自动生成。
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
                placeholder="点击「生成并复制」获取专属安装命令"
              />
            </div>

            <p className="flex items-start gap-2 text-sm text-muted-foreground">
              <Terminal className="mt-0.5 h-4 w-4 shrink-0 text-foreground/70" />
              {commandFooter}
            </p>

            {response ? (
              <div className="space-y-1 rounded-md bg-muted/30 p-3 text-xs text-muted-foreground">
                <p>
                  节点 ID：
                  <span className="font-mono text-foreground">
                    {response.nodeId ?? "安装时自动生成"}
                  </span>
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
              3
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
              脚本会生成 <code>{`anyproxy-edge-${response?.nodeId ?? "<自动生成的节点ID>"}.service`}</code>{" "}
              与{" "}
              <code>{`anyproxy-tunnel-${response?.nodeId ?? "<自动生成的节点ID>"}.service`}</code>，确保服务状态为 active。
            </li>
            <li>
              如需卸载，可执行{" "}
              <code>{`sudo systemctl disable --now anyproxy-edge-${response?.nodeId ?? "<自动生成的节点ID>"}`}</code>{" "}
              与{" "}
              <code>{`sudo systemctl disable --now anyproxy-tunnel-${response?.nodeId ?? "<自动生成的节点ID>"}`}</code>{" "}
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
                脚本无需临时令牌，请确保控制平面地址及可选的 Agent 访问令牌仅对受信网络可见；如泄露，可立即变更控制平面入口或刷新访问令牌。
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}
