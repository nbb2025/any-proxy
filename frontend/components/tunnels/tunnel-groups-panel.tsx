"use client"

import { useMemo, useState } from "react"
import { formatDistanceToNowStrict } from "date-fns"
import type { EdgeNode, TunnelGroup } from "@/lib/types"
import type { TunnelGroupPayload } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
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
import { ScrollArea } from "@/components/ui/scroll-area"

const TRANSPORT_OPTIONS = [
  { label: "QUIC", value: "quic" },
  { label: "TCP", value: "tcp" },
  { label: "WebSocket", value: "websocket" },
]

export type NodeHeartbeatMap = Record<string, { online: boolean; lastSeen?: string }>

interface TunnelGroupsPanelProps {
  groups: TunnelGroup[]
  nodes: EdgeNode[]
  nodeStatus: NodeHeartbeatMap
  pending?: boolean
  onCreate: (payload: TunnelGroupPayload) => Promise<void>
  onUpdate: (id: string, payload: TunnelGroupPayload) => Promise<void>
  onDelete: (id: string) => Promise<void>
}

interface GroupFormState {
  name: string
  description: string
  listenAddress: string
  transports: string[]
  enableCompress: boolean
  edgeNodeIds: string[]
}

const defaultFormState: GroupFormState = {
  name: "",
  description: "",
  listenAddress: "0.0.0.0:4433",
  transports: ["quic", "tcp"],
  enableCompress: false,
  edgeNodeIds: [],
}

export function TunnelGroupsPanel({
  groups,
  nodes,
  nodeStatus,
  pending,
  onCreate,
  onUpdate,
  onDelete,
}: TunnelGroupsPanelProps) {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [formState, setFormState] = useState<GroupFormState>(defaultFormState)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const selectableNodes = useMemo(() => nodes.filter((node) => node.category !== "waiting"), [nodes])

  const openCreateDialog = () => {
    setFormState(defaultFormState)
    setEditingId(null)
    setDialogOpen(true)
  }

  const openEditDialog = (group: TunnelGroup) => {
    setFormState({
      name: group.name,
      description: group.description ?? "",
      listenAddress: group.listenAddress || "0.0.0.0:4433",
      transports: group.transports?.length ? group.transports : ["quic", "tcp"],
      enableCompress: Boolean(group.enableCompress),
      edgeNodeIds: [...group.edgeNodeIds],
    })
    setEditingId(group.id)
    setDialogOpen(true)
  }

  const handleSubmit = async () => {
    if (!formState.name.trim()) {
      return
    }
    setSubmitting(true)
    const payload: TunnelGroupPayload = {
      name: formState.name.trim(),
      description: formState.description.trim() || undefined,
      listenAddress: formState.listenAddress.trim() || undefined,
      transports: formState.transports,
      edgeNodeIds: formState.edgeNodeIds,
      enableCompress: formState.enableCompress,
    }
    try {
      if (editingId) {
        await onUpdate(editingId, payload)
      } else {
        await onCreate(payload)
      }
      setDialogOpen(false)
      setFormState(defaultFormState)
      setEditingId(null)
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async () => {
    if (!deletingId) return
    setDeleting(true)
    try {
      await onDelete(deletingId)
      setDeletingId(null)
    } finally {
      setDeleting(false)
    }
  }

  const renderEdgeSummary = (group: TunnelGroup) => {
    if (group.edgeNodeIds.length === 0) {
      return <span className="text-sm text-muted-foreground">自动调度</span>
    }
    const online = group.edgeNodeIds.filter((id) => nodeStatus[id]?.online).length
    return (
      <span className="text-sm text-muted-foreground">
        {online}/{group.edgeNodeIds.length} 在线
      </span>
    )
  }

  return (
    <Card className="border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <div>
          <h2 className="text-lg font-semibold text-foreground">隧道分组</h2>
          <p className="text-sm text-muted-foreground">定义 edge-agent 监听入口与候选节点。</p>
        </div>
        <Button onClick={openCreateDialog} disabled={pending}>新建分组</Button>
      </div>

      {groups.length === 0 ? (
        <div className="p-6 text-sm text-muted-foreground">尚未配置隧道分组，可通过此处快速创建。</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase text-muted-foreground">
                <th className="px-6 py-3 text-left">名称</th>
                <th className="px-6 py-3 text-left">监听地址</th>
                <th className="px-6 py-3 text-left">绑定节点</th>
                <th className="px-6 py-3 text-left">传输协议</th>
                <th className="px-6 py-3 text-left">压缩</th>
                <th className="px-6 py-3 text-left">更新时间</th>
                <th className="px-6 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((group) => (
                <tr key={group.id} className="border-b border-border/60 last:border-0">
                  <td className="px-6 py-4 align-top">
                    <div className="font-medium text-foreground">{group.name}</div>
                    <p className="text-xs text-muted-foreground">ID: {group.id}</p>
                  </td>
                  <td className="px-6 py-4 align-top">{group.listenAddress}</td>
                  <td className="px-6 py-4 align-top">
                    <div className="space-y-1">
                      {group.edgeNodeIds.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {group.edgeNodeIds.map((nodeId) => (
                            <Badge key={nodeId} variant={nodeStatus[nodeId]?.online ? "default" : "secondary"}>
                              {nodeId}
                            </Badge>
                          ))}
                        </div>
                      ) : null}
                      {renderEdgeSummary(group)}
                    </div>
                  </td>
                  <td className="px-6 py-4 align-top">
                    <div className="flex flex-wrap gap-1">
                      {(group.transports?.length ? group.transports : ["quic", "tcp"]).map((transport) => (
                        <Badge key={transport} variant="outline">
                          {transport.toUpperCase()}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4 align-top">
                    {group.enableCompress ? <Badge variant="secondary">启用</Badge> : <span className="text-muted-foreground">关闭</span>}
                  </td>
                  <td className="px-6 py-4 align-top text-muted-foreground">
                    {group.updatedAt ? formatDistanceToNowStrict(new Date(group.updatedAt), { addSuffix: true }) : "—"}
                  </td>
                  <td className="px-6 py-4 align-top text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => openEditDialog(group)} disabled={pending}>
                        编辑
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        disabled={pending}
                        onClick={() => setDeletingId(group.id)}
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
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>{editingId ? "编辑隧道分组" : "新建隧道分组"}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-3">
              <Label htmlFor="group-name">名称</Label>
              <Input
                id="group-name"
                value={formState.name}
                onChange={(event) => setFormState((prev) => ({ ...prev, name: event.target.value }))}
                placeholder="如 华北隧道入口"
              />
              <Label htmlFor="group-listen">监听地址</Label>
              <Input
                id="group-listen"
                value={formState.listenAddress}
                onChange={(event) => setFormState((prev) => ({ ...prev, listenAddress: event.target.value }))}
                placeholder="0.0.0.0:4433"
              />
              <Label>传输协议</Label>
              <div className="space-y-2 rounded-md border border-border p-3">
                {TRANSPORT_OPTIONS.map((option) => {
                  const checked = formState.transports.includes(option.value)
                  return (
                    <label key={option.value} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={checked}
                        onCheckedChange={() => {
                          setFormState((prev) => {
                            const transports = checked
                              ? prev.transports.filter((item) => item !== option.value)
                              : [...prev.transports, option.value]
                            return { ...prev, transports }
                          })
                        }}
                      />
                      {option.label}
                    </label>
                  )
                })}
              </div>
              <div className="flex items-center justify-between rounded-md border border-border p-3">
                <div>
                  <p className="text-sm font-medium text-foreground">启用压缩</p>
                  <p className="text-xs text-muted-foreground">在带宽紧张时可减小开销，需客户端同样支持。</p>
                </div>
                <Switch
                  checked={formState.enableCompress}
                  onCheckedChange={(value) => setFormState((prev) => ({ ...prev, enableCompress: Boolean(value) }))}
                />
              </div>
            </div>
            <div className="space-y-3">
              <Label>可用 Edge 节点</Label>
              <ScrollArea className="h-56 rounded-md border border-border">
                <div className="divide-y divide-border/60">
                  {selectableNodes.length === 0 ? (
                    <p className="p-3 text-sm text-muted-foreground">暂无可用节点</p>
                  ) : (
                    selectableNodes.map((node) => {
                      const checked = formState.edgeNodeIds.includes(node.id)
                      const status = nodeStatus[node.id]
                      return (
                        <label key={node.id} className="flex cursor-pointer items-center gap-2 px-3 py-2 text-sm">
                          <Checkbox
                            checked={checked}
                            onCheckedChange={() => {
                              setFormState((prev) => {
                                const edgeNodeIds = checked
                                  ? prev.edgeNodeIds.filter((item) => item !== node.id)
                                  : [...prev.edgeNodeIds, node.id]
                                return { ...prev, edgeNodeIds }
                              })
                            }}
                          />
                          <div className="flex flex-col">
                            <span className="font-medium text-foreground">{node.name || node.id}</span>
                            <span className="text-xs text-muted-foreground">
                              {status?.online ? "在线" : "离线"} · 最近 {status?.lastSeen ? formatDistanceToNowStrict(new Date(status.lastSeen), { addSuffix: true }) : "未知"}
                            </span>
                          </div>
                        </label>
                      )
                    })
                  )}
                </div>
              </ScrollArea>
              <Label htmlFor="group-desc">描述</Label>
              <Textarea
                id="group-desc"
                value={formState.description}
                onChange={(event) => setFormState((prev) => ({ ...prev, description: event.target.value }))}
                rows={4}
                placeholder="用于说明用途或关联的业务集群"
              />
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

      <AlertDialog open={!!deletingId} onOpenChange={(open) => !open && setDeletingId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除隧道分组</AlertDialogTitle>
            <AlertDialogDescription>删除后对应 edge-agent 将不再监听该入口，确认继续？</AlertDialogDescription>
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
