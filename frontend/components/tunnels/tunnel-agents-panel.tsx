"use client"

import { useMemo, useState } from "react"
import { formatDistanceToNowStrict } from "date-fns"
import { Plus, RefreshCw, Trash2 } from "lucide-react"
import type { EdgeNode, TunnelAgent, TunnelGroup } from "@/lib/types"
import type { TunnelAgentPayload } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { ScrollArea } from "@/components/ui/scroll-area"
import { NodeHeartbeatMap } from "./tunnel-groups-panel"

interface TunnelAgentsPanelProps {
  agents: TunnelAgent[]
  groups: TunnelGroup[]
  nodes: EdgeNode[]
  nodeStatus: NodeHeartbeatMap
  pending?: boolean
  onCreate: (payload: TunnelAgentPayload) => Promise<string | undefined>
  onUpdate: (id: string, payload: TunnelAgentPayload) => Promise<string | undefined>
  onDelete: (id: string) => Promise<void>
  onRefreshKey: (id: string) => Promise<string>
}

interface ServiceFormState {
  id: string
  protocol: string
  localAddress: string
  localPort: string
  remotePort: string
  enableCompression: boolean
  description?: string
}

interface AgentFormState {
  nodeId: string
  groupId: string
  description: string
  enabled: boolean
  rotateKey: boolean
  services: ServiceFormState[]
}

const defaultService: ServiceFormState = {
  id: "svc-1",
  protocol: "tcp",
  localAddress: "127.0.0.1",
  localPort: "8080",
  remotePort: "0",
  enableCompression: false,
}

const defaultAgentState: AgentFormState = {
  nodeId: "",
  groupId: "",
  description: "",
  enabled: true,
  rotateKey: false,
  services: [defaultService],
}

const ONLINE_THRESHOLD_MS = 120_000

export function TunnelAgentsPanel({
  agents,
  groups,
  nodes,
  nodeStatus,
  pending,
  onCreate,
  onUpdate,
  onDelete,
  onRefreshKey,
}: TunnelAgentsPanelProps) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formState, setFormState] = useState<AgentFormState>(defaultAgentState)
  const [submitting, setSubmitting] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [issuedKey, setIssuedKey] = useState<{ agentId: string; key: string } | null>(null)
  const [refreshingKeyId, setRefreshingKeyId] = useState<string | null>(null)

  const groupMap = useMemo(() => Object.fromEntries(groups.map((group) => [group.id, group])), [groups])
  const nodeMap = useMemo(() => Object.fromEntries(nodes.map((node) => [node.id, node])), [nodes])

  const openCreateDialog = () => {
    setFormState(defaultAgentState)
    setEditingId(null)
    setDialogOpen(true)
  }

  const openEditDialog = (agent: TunnelAgent) => {
    setFormState({
      nodeId: agent.nodeId,
      groupId: agent.groupId,
      description: agent.description ?? "",
      enabled: agent.enabled,
      rotateKey: false,
      services:
        agent.services.length > 0
          ? agent.services.map((svc) => ({
              id: svc.id,
              protocol: svc.protocol ?? "tcp",
              localAddress: svc.localAddress,
              localPort: String(svc.localPort ?? ""),
              remotePort: String(svc.remotePort ?? ""),
              enableCompression: Boolean(svc.enableCompression),
              description: svc.description,
            }))
          : [defaultService],
    })
    setEditingId(agent.id)
    setDialogOpen(true)
  }

  const updateService = (index: number, patch: Partial<ServiceFormState>) => {
    setFormState((prev) => {
      const next = [...prev.services]
      next[index] = { ...next[index], ...patch }
      return { ...prev, services: next }
    })
  }

  const removeService = (index: number) => {
    setFormState((prev) => {
      if (prev.services.length === 1) return prev
      const next = prev.services.filter((_, idx) => idx !== index)
      return { ...prev, services: next }
    })
  }

  const addService = () => {
    setFormState((prev) => ({
      ...prev,
      services: [
        ...prev.services,
        {
          ...defaultService,
          id: `svc-${prev.services.length + 1}`,
          remotePort: "0",
        },
      ],
    }))
  }

  const handleSubmit = async () => {
    if (!formState.nodeId.trim() || !formState.groupId.trim()) return
    const servicesPayload = formState.services
      .filter((svc) => svc.id.trim())
      .map((svc) => ({
        id: svc.id.trim(),
        protocol: svc.protocol,
        localAddress: svc.localAddress.trim() || "127.0.0.1",
        localPort: Number(svc.localPort) || undefined,
        remotePort: Number(svc.remotePort) || 0,
        enableCompression: svc.enableCompression,
        description: svc.description?.trim() || undefined,
      }))
      .filter((svc) => svc.remotePort > 0)
    if (servicesPayload.length === 0) {
      return
    }
    setSubmitting(true)
    const payload: TunnelAgentPayload = {
      nodeId: formState.nodeId.trim(),
      groupId: formState.groupId.trim(),
      description: formState.description.trim() || undefined,
      enabled: formState.enabled,
      rotateKey: editingId ? formState.rotateKey : undefined,
      services: servicesPayload,
    }
    try {
      const key = editingId ? await onUpdate(editingId, payload) : await onCreate(payload)
      if (key) {
        setIssuedKey({ agentId: editingId ?? formState.nodeId.trim(), key })
      }
      setDialogOpen(false)
      setEditingId(null)
      setFormState(defaultAgentState)
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    setDeleting(true)
    try {
      await onDelete(deleteId)
      setDeleteId(null)
    } finally {
      setDeleting(false)
    }
  }

  const handleRefreshKey = async (agentId: string) => {
    setRefreshingKeyId(agentId)
    try {
      const key = await onRefreshKey(agentId)
      setIssuedKey({ agentId, key })
    } finally {
      setRefreshingKeyId(null)
    }
  }

  const onlineAgents = useMemo(() => {
    return agents.filter((agent) => {
      const lastSeen = nodeStatus[agent.nodeId]?.lastSeen
      if (!lastSeen) return false
      return Date.now() - new Date(lastSeen).getTime() <= ONLINE_THRESHOLD_MS
    }).length
  }, [agents, nodeStatus])

  const renderStatus = (agent: TunnelAgent) => {
    const status = nodeStatus[agent.nodeId]
    if (!status?.lastSeen) {
      return <Badge variant="outline">未知</Badge>
    }
    const online = status.online
    return (
      <div className="flex items-center gap-2">
        <Badge variant={online ? "default" : "secondary"}>{online ? "在线" : "离线"}</Badge>
        <span className="text-xs text-muted-foreground">
          {formatDistanceToNowStrict(new Date(status.lastSeen), { addSuffix: true })}
        </span>
      </div>
    )
  }

  return (
    <Card className="border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Tunnel Agent</h2>
          <p className="text-sm text-muted-foreground">
            管理内网客户端及其暴露的服务，统计在线会话与心跳。
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-sm text-muted-foreground">
            在线 {onlineAgents}/{agents.length}
          </div>
          <Button onClick={openCreateDialog} disabled={pending}>注册 Agent</Button>
        </div>
      </div>

      {issuedKey ? (
        <Alert className="m-6">
          <AlertTitle>新密钥（仅显示一次）</AlertTitle>
            <AlertDescription className="flex flex-wrap items-center gap-3">
              <code className="rounded bg-muted px-2 py-1 text-sm">{issuedKey.key}</code>
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  if (typeof navigator === "undefined" || !navigator.clipboard) return
                  try {
                    await navigator.clipboard.writeText(issuedKey.key)
                  } catch {
                    // ignore
                  }
                }}
              >
                复制
              </Button>
            <span className="text-xs text-muted-foreground">Agent: {issuedKey.agentId}</span>
          </AlertDescription>
        </Alert>
      ) : null}

      {agents.length === 0 ? (
        <div className="p-6 text-sm text-muted-foreground">暂无 Agent，可先在控制面登记后发放安装命令。</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase text-muted-foreground">
                <th className="px-6 py-3 text-left">Agent</th>
                <th className="px-6 py-3 text-left">分组</th>
                <th className="px-6 py-3 text-left">服务</th>
                <th className="px-6 py-3 text-left">会话状态</th>
                <th className="px-6 py-3 text-left">Key 版本</th>
                <th className="px-6 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.id} className="border-b border-border/60 last:border-0">
                  <td className="px-6 py-4 align-top">
                    <div className="font-medium text-foreground">{agent.nodeId}</div>
                    <p className="text-xs text-muted-foreground">{agent.description || "—"}</p>
                  </td>
                  <td className="px-6 py-4 align-top">
                    {groupMap[agent.groupId]?.name ?? agent.groupId}
                  </td>
                  <td className="px-6 py-4 align-top">
                    <div className="flex flex-wrap gap-1">
                      {(agent.services ?? []).map((svc) => (
                        <Badge key={svc.id} variant="outline">
                          {svc.id}:{svc.remotePort}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4 align-top">{renderStatus(agent)}</td>
                  <td className="px-6 py-4 align-top">v{agent.keyVersion ?? 1}</td>
                  <td className="px-6 py-4 align-top">
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => openEditDialog(agent)} disabled={pending}>
                        编辑
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => void handleRefreshKey(agent.id)}
                        disabled={pending || refreshingKeyId === agent.id}
                      >
                        <RefreshCw className="mr-1 h-3 w-3" /> 刷新 key
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => setDeleteId(agent.id)}
                        disabled={pending}
                      >
                        删除
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={(open) => !open && setDialogOpen(false)}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>{editingId ? "编辑 Agent" : "注册 Agent"}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <Label htmlFor="agent-node">节点 ID</Label>
              <Input
                id="agent-node"
                value={formState.nodeId}
                onChange={(event) => setFormState((prev) => ({ ...prev, nodeId: event.target.value }))}
                placeholder="与安装脚本一致"
              />
              <Label>分组</Label>
              <Select value={formState.groupId} onValueChange={(value) => setFormState((prev) => ({ ...prev, groupId: value }))}>
                <SelectTrigger>
                  <SelectValue placeholder="选择分组" />
                </SelectTrigger>
                <SelectContent>
                  {groups.map((group) => (
                    <SelectItem key={group.id} value={group.id}>
                      {group.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Label htmlFor="agent-desc">描述</Label>
              <Textarea
                id="agent-desc"
                rows={4}
                value={formState.description}
                onChange={(event) => setFormState((prev) => ({ ...prev, description: event.target.value }))}
                placeholder="可选：备注机房/用途"
              />
              <div className="flex items-center justify-between rounded-md border border-border p-3">
                <div>
                  <p className="text-sm font-medium text-foreground">启用 Agent</p>
                  <p className="text-xs text-muted-foreground">关闭后连接会被拒绝。</p>
                </div>
                <Switch checked={formState.enabled} onCheckedChange={(value) => setFormState((prev) => ({ ...prev, enabled: Boolean(value) }))} />
              </div>
              {editingId ? (
                <div className="flex items-center justify-between rounded-md border border-border p-3">
                  <div>
                    <p className="text-sm font-medium text-foreground">保存时刷新 key</p>
                    <p className="text-xs text-muted-foreground">启用后，下发新的 Agent Key。</p>
                  </div>
                  <Switch
                    checked={formState.rotateKey}
                    onCheckedChange={(value) => setFormState((prev) => ({ ...prev, rotateKey: Boolean(value) }))}
                  />
                </div>
              ) : null}
            </div>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <Label>暴露服务</Label>
                <Button variant="outline" size="sm" onClick={addService}>
                  <Plus className="mr-1 h-4 w-4" /> 添加服务
                </Button>
              </div>
              <ScrollArea className="h-72 rounded-md border border-border">
                <div className="divide-y divide-border/60">
                  {formState.services.map((svc, index) => (
                    <div key={svc.id} className="space-y-2 px-3 py-3">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-foreground">Service #{index + 1}</span>
                        {formState.services.length > 1 ? (
                          <Button variant="ghost" size="icon" onClick={() => removeService(index)}>
                            <Trash2 className="h-4 w-4 text-muted-foreground" />
                          </Button>
                        ) : null}
                      </div>
                      <Input
                        value={svc.id}
                        onChange={(event) => updateService(index, { id: event.target.value })}
                        placeholder="服务 ID"
                      />
                      <div className="grid gap-2 md:grid-cols-2">
                        <div>
                          <Label className="text-xs text-muted-foreground">协议</Label>
                          <Select value={svc.protocol} onValueChange={(value) => updateService(index, { protocol: value })}>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="tcp">TCP</SelectItem>
                              <SelectItem value="udp">UDP</SelectItem>
                              <SelectItem value="quic">QUIC</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label className="text-xs text-muted-foreground">远端端口</Label>
                          <Input
                            value={svc.remotePort}
                            onChange={(event) => updateService(index, { remotePort: event.target.value })}
                            placeholder="公网端口"
                          />
                        </div>
                      </div>
                      <div className="grid gap-2 md:grid-cols-2">
                        <div>
                          <Label className="text-xs text-muted-foreground">本地地址</Label>
                          <Input
                            value={svc.localAddress}
                            onChange={(event) => updateService(index, { localAddress: event.target.value })}
                            placeholder="127.0.0.1"
                          />
                        </div>
                        <div>
                          <Label className="text-xs text-muted-foreground">本地端口</Label>
                          <Input
                            value={svc.localPort}
                            onChange={(event) => updateService(index, { localPort: event.target.value })}
                            placeholder="8080"
                          />
                        </div>
                      </div>
                      <div className="flex items-center justify-between rounded-md border border-border/80 px-3 py-2">
                        <span className="text-xs text-muted-foreground">启用压缩</span>
                        <Switch
                          checked={svc.enableCompression}
                          onCheckedChange={(value) => updateService(index, { enableCompression: Boolean(value) })}
                        />
                      </div>
                      <Textarea
                        value={svc.description || ""}
                        onChange={(event) => updateService(index, { description: event.target.value })}
                        rows={2}
                        placeholder="描述 (可选)"
                      />
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={submitting}>
              取消
            </Button>
            <Button onClick={handleSubmit} disabled={submitting}>
              {editingId ? "保存" : "创建"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteId} onOpenChange={(open) => !open && setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除 Agent</AlertDialogTitle>
            <AlertDialogDescription>删除后客户端需重新安装并分配 Key，确认继续？</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} disabled={deleting}>
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
