'use client'

import Link from "next/link"
import { useMemo, useState } from "react"
import { useRouter } from "next/navigation"
import { ArrowLeft, Info, Plus, Trash2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"
import { createDomainRequest, type DomainRequestPayload } from "@/lib/api"
import { useSnapshot } from "@/hooks/use-snapshot"
import type { EdgeNode } from "@/lib/types"
import { Checkbox } from "@/components/ui/checkbox"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"

type ForwardMode = "single" | "load_balancing"

interface ListenerPair {
  id: string
  inboundProtocol: "HTTP" | "HTTPS"
  inboundPort: string
  outboundProtocol: "HTTP" | "HTTPS"
  outboundPort: string
}

interface UpstreamEntry {
  id: string
  host: string
}

const createId = () => {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID()
  }
  return `id-${Math.random().toString(36).slice(2, 10)}`
}

const createListenerPair = (): ListenerPair => ({
  id: createId(),
  inboundProtocol: "HTTPS",
  inboundPort: "443",
  outboundProtocol: "HTTP",
  outboundPort: "80",
})

const createUpstreamEntry = (): UpstreamEntry => ({
  id: createId(),
  host: "",
})

export default function CreateDomainPage() {
  const router = useRouter()
  const { snapshot } = useSnapshot()
  const cdnNodes = useMemo(() => snapshot?.nodes?.filter((node) => node.category === "cdn") ?? [], [snapshot])

  const [form, setForm] = useState({
    displayName: "",
    remark: "",
    domain: "",
    selectedNodes: [] as string[],
    forwardMode: "single" as ForwardMode,
    algorithm: "round_robin",
    singleHost: "",
    upstreams: [createUpstreamEntry()],
    listenerPairs: [createListenerPair()],
  })
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const updateForm = (patch: Partial<typeof form>) => setForm((prev) => ({ ...prev, ...patch }))

  const updateUpstream = (id: string, value: string) => {
    setForm((prev) => ({
      ...prev,
      upstreams: prev.upstreams.map((entry) => (entry.id === id ? { ...entry, host: value } : entry)),
    }))
  }

  const addUpstream = () => {
    setForm((prev) => ({
      ...prev,
      upstreams: [...prev.upstreams, createUpstreamEntry()],
    }))
  }

  const removeUpstream = (id: string) => {
    setForm((prev) => {
      if (prev.upstreams.length <= 1) return prev
      return {
        ...prev,
        upstreams: prev.upstreams.filter((entry) => entry.id !== id),
      }
    })
  }

  const updateListenerPair = (id: string, patch: Partial<ListenerPair>) => {
    setForm((prev) => ({
      ...prev,
      listenerPairs: prev.listenerPairs.map((pair) => (pair.id === id ? { ...pair, ...patch } : pair)),
    }))
  }

  const addListenerPair = () => {
    setForm((prev) => ({
      ...prev,
      listenerPairs: [...prev.listenerPairs, createListenerPair()],
    }))
  }

  const removeListenerPair = (id: string) => {
    setForm((prev) => {
      if (prev.listenerPairs.length <= 1) return prev
      return {
        ...prev,
        listenerPairs: prev.listenerPairs.filter((pair) => pair.id !== id),
      }
    })
  }

  const handleSubmit = async () => {
    const trimmedDomain = form.domain.trim()
    if (!trimmedDomain) {
      setError("请输入域名")
      return
    }
    const listenerPairs = form.listenerPairs.filter(
      (pair) => pair.inboundPort.trim() && pair.outboundPort.trim(),
    )
    if (listenerPairs.length === 0) {
      setError("至少配置一个传输协议与端口映射")
      return
    }

    const upstreamHosts =
      form.forwardMode === "load_balancing"
        ? form.upstreams.map((entry) => entry.host.trim()).filter(Boolean)
        : [form.singleHost.trim()].filter(Boolean)
    if (upstreamHosts.length === 0) {
      setError("请至少填写一个回源地址（不含端口）")
      return
    }

    const inboundListeners = listenerPairs.map((pair) => ({
      protocol: pair.inboundProtocol,
      port: parsePort(pair.inboundPort, pair.inboundProtocol),
    }))
    const outboundListeners = listenerPairs.map((pair) => ({
      protocol: pair.outboundProtocol,
      port: parsePort(pair.outboundPort, pair.outboundProtocol),
    }))
    const enableTls = inboundListeners.some((listener) => listener.protocol === "HTTPS")
    const outboundPort = outboundListeners.length > 0 ? outboundListeners[0].port : 80

    const metadata: DomainRequestPayload["metadata"] = {
      displayName: form.displayName.trim() || undefined,
      remark: form.remark.trim() || undefined,
      forwardMode: form.forwardMode,
      loadBalancingAlgorithm:
        form.forwardMode === "load_balancing" ? form.algorithm.trim().toLowerCase() : undefined,
      inboundListeners,
      outboundListeners,
    }

    const payload: DomainRequestPayload = {
      domain: trimmedDomain,
      enableTls,
      edgeNodes: form.selectedNodes,
      upstreams: upstreamHosts.map((host) => ({ address: `${host}:${outboundPort}` })),
      metadata,
    }

    setSubmitting(true)
    setError(null)
    try {
      const token = await ensureAccessToken()
      if (!token) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      await createDomainRequest(token, payload)
      router.push("/resources?tab=l7")
    } catch (err) {
      const status = (err as { status?: number }).status
      if (status === 401) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      setError(err instanceof Error ? err.message : "保存失败，请稍后重试")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-8">
      <header className="flex items-start justify-between gap-4 border-b border-border/60 pb-6">
        <div className="flex items-center gap-3">
          <Link
            href="/resources?tab=l7"
            className="flex h-10 w-10 items-center justify-center rounded-full border border-border text-muted-foreground transition hover:bg-muted/60"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground/70">Application Proxy</p>
            <h1 className="text-2xl font-semibold text-foreground">新增 L7 应用代理</h1>
            <p className="text-sm text-muted-foreground">
              完整配置请求域名、回源策略与传输协议，保存后会自动同步至匹配的 Edge 节点。
            </p>
          </div>
        </div>
      </header>

      <section className="rounded-2xl border border-border/60 bg-card/80 p-6 shadow-sm">
        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="space-y-4 border border-border/80 bg-background/70 p-6">
            <div>
              <p className="text-sm font-semibold text-foreground">基本信息</p>
              <p className="text-xs text-muted-foreground">用于控制台展示与检索，不影响实际转发。</p>
            </div>
            <div className="grid gap-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Field label="名称">
                  <Input
                    placeholder="例如：官网入口"
                    value={form.displayName}
                    onChange={(event) => updateForm({ displayName: event.target.value })}
                  />
                </Field>
                <Field label="域名" required>
                  <Input
                    placeholder="www.example.com"
                    value={form.domain}
                    onChange={(event) => updateForm({ domain: event.target.value })}
                  />
                </Field>
              </div>
              <Field label="备注">
                <Textarea
                  placeholder="描述用途、灰度策略等信息"
                  value={form.remark}
                  onChange={(event) => updateForm({ remark: event.target.value })}
                  rows={3}
                />
              </Field>
              <Field label="指定节点（CDN）" hint="支持多选；留空表示全部 CDN 节点">
                <NodeMultiSelect
                  nodes={cdnNodes}
                  value={form.selectedNodes}
                  onChange={(value) => updateForm({ selectedNodes: value })}
                />
              </Field>
            </div>
          </Card>

          <Card className="space-y-4 border border-border/80 bg-background/70 p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-foreground">请求配置</p>
                <p className="text-xs text-muted-foreground">配置入口协议与端口，可添加多个监听。</p>
              </div>
              <Button type="button" variant="outline" size="sm" onClick={addListenerPair}>
                <Plus className="mr-2 h-4 w-4" />
                新增
              </Button>
            </div>
            <div className="space-y-3">
              {form.listenerPairs.map((pair, index) => (
                <div key={pair.id} className="rounded-2xl border border-border/70 bg-card/70 p-4">
                  <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
                    <span>监听 #{index + 1}</span>
                    {form.listenerPairs.length > 1 ? (
                      <Button type="button" variant="ghost" size="icon" onClick={() => removeListenerPair(pair.id)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    ) : null}
                  </div>
                  <div className="grid gap-3 md:grid-cols-2">
                    <SelectorField
                      label="请求协议与端口"
                      protocol={pair.inboundProtocol}
                      port={pair.inboundPort}
                      onProtocolChange={(value) => updateListenerPair(pair.id, { inboundProtocol: value })}
                      onPortChange={(value) => updateListenerPair(pair.id, { inboundPort: value })}
                    />
                    <SelectorField
                      label="转发协议与端口"
                      protocol={pair.outboundProtocol}
                      port={pair.outboundPort}
                      onProtocolChange={(value) => updateListenerPair(pair.id, { outboundProtocol: value })}
                      onPortChange={(value) => updateListenerPair(pair.id, { outboundPort: value })}
                    />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </section>

      <section className="rounded-2xl border border-border/60 bg-card/80 p-6 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-semibold text-foreground">转发配置</p>
            <p className="text-xs text-muted-foreground">支持单一回源或多节点负载均衡。</p>
          </div>
          <div className="flex gap-2">
            <ModeButton
              label="单一回源"
              active={form.forwardMode === "single"}
              onClick={() => updateForm({ forwardMode: "single" })}
            />
            <ModeButton
              label="负载均衡"
              active={form.forwardMode === "load_balancing"}
              onClick={() => updateForm({ forwardMode: "load_balancing" })}
            />
          </div>
        </div>
        <div className="mt-4 space-y-4">
          {form.forwardMode === "load_balancing" ? (
            <Field label="负载均衡算法">
              <Select value={form.algorithm} onValueChange={(value) => updateForm({ algorithm: value })}>
                <SelectTrigger>
                  <SelectValue placeholder="算法" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="round_robin">轮询 (Round Robin)</SelectItem>
                  <SelectItem value="least_conn">最少连接 (Least Conn)</SelectItem>
                  <SelectItem value="ip_hash">IP Hash</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          ) : null}

          {form.forwardMode === "single" ? (
            <Field label="回源地址" hint="填写域名或 IP，不含端口" required>
              <Input
                placeholder="origin.example.com"
                value={form.singleHost}
                onChange={(event) => updateForm({ singleHost: event.target.value })}
              />
            </Field>
          ) : (
            <Field label="回源地址列表" hint="每行一个域名或 IP，不含端口">
              <div className="space-y-3">
                {form.upstreams.map((entry) => (
                  <div key={entry.id} className="flex items-center gap-2">
                    <Input
                      placeholder="origin.example.com"
                      value={entry.host}
                      onChange={(event) => updateUpstream(entry.id, event.target.value)}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      disabled={form.upstreams.length <= 1}
                      onClick={() => removeUpstream(entry.id)}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                ))}
                <Button type="button" variant="outline" size="sm" onClick={addUpstream} className="w-fit">
                  <Plus className="mr-2 h-4 w-4" />
                  添加回源
                </Button>
              </div>
            </Field>
          )}
        </div>
      </section>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      <div className="flex gap-3">
        <Button variant="outline" asChild disabled={submitting}>
          <Link href="/resources?tab=l7">取消</Link>
        </Button>
        <Button onClick={handleSubmit} disabled={submitting}>
          {submitting ? "保存中..." : "保存并下发"}
        </Button>
      </div>
    </div>
  )
}

function Field({
  label,
  hint,
  required,
  children,
}: {
  label: string
  hint?: string
  required?: boolean
  children: React.ReactNode
}) {
  return (
    <div className="space-y-2">
      <Label className="flex items-center gap-2 text-sm text-muted-foreground">
        {label}
        {required ? <span className="text-destructive">*</span> : null}
        {hint ? (
          <span className="flex items-center text-xs text-muted-foreground/70">
            <Info className="mr-1 h-3 w-3" />
            {hint}
          </span>
        ) : null}
      </Label>
      {children}
    </div>
  )
}

function SelectorField({
  label,
  protocol,
  port,
  onProtocolChange,
  onPortChange,
}: {
  label: string
  protocol: "HTTP" | "HTTPS"
  port: string
  onProtocolChange: (value: "HTTP" | "HTTPS") => void
  onPortChange: (value: string) => void
}) {
  return (
    <Field label={label}>
      <div className="flex gap-2">
        <Select value={protocol} onValueChange={onProtocolChange}>
          <SelectTrigger className="w-32">
            <SelectValue placeholder="协议" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="HTTP">HTTP</SelectItem>
            <SelectItem value="HTTPS">HTTPS</SelectItem>
          </SelectContent>
        </Select>
        <Input value={port} onChange={(event) => onPortChange(event.target.value)} />
      </div>
    </Field>
  )
}

function ModeButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <Button
      type="button"
      variant={active ? "default" : "outline"}
      className={active ? "shadow-md" : "bg-muted/40"}
      onClick={onClick}
    >
      {label}
    </Button>
  )
}

function NodeMultiSelect({
  nodes,
  value,
  onChange,
}: {
  nodes: EdgeNode[]
  value: string[]
  onChange: (value: string[]) => void
}) {
  const [open, setOpen] = useState(false)
  const toggleNode = (id: string) => {
    onChange(value.includes(id) ? value.filter((item) => item !== id) : [...value, id])
  }
  const selectAll = () => onChange(nodes.map((node) => node.id))
  const clear = () => onChange([])
  const summary =
    value.length === 0 ? "全部 CDN 节点" : value.length === nodes.length ? "已选全部 CDN 节点" : `已选 ${value.length} 个节点`

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" className="w-full justify-between">
          {summary}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-72 p-0" align="start">
        <div className="flex items-center justify-between border-b border-border px-3 py-2 text-xs text-muted-foreground">
          <button onClick={selectAll} className="hover:text-foreground">
            全选
          </button>
          <button onClick={clear} className="hover:text-foreground">
            清空
          </button>
        </div>
        <div className="max-h-64 space-y-1 overflow-y-auto p-3">
          {nodes.length === 0 ? (
            <p className="text-xs text-muted-foreground">无 CDN 节点</p>
          ) : (
            nodes.map((node) => (
              <label key={node.id} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 hover:bg-muted/60">
                <Checkbox
                  checked={value.includes(node.id)}
                  onCheckedChange={() => toggleNode(node.id)}
                  className="h-4 w-4"
                />
                <div className="flex flex-col">
                  <span className="text-sm text-foreground">{node.name || node.id}</span>
                  <span className="text-xs text-muted-foreground">{node.id}</span>
                </div>
              </label>
            ))
          )}
        </div>
      </PopoverContent>
    </Popover>
  )
}

function parsePort(value: string, protocol: "HTTP" | "HTTPS"): number {
  const parsed = Number(value.trim())
  if (Number.isFinite(parsed) && parsed > 0 && parsed <= 65535) {
    return parsed
  }
  return protocol === "HTTPS" ? 443 : 80
}
