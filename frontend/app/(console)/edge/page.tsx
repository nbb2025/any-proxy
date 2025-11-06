'use client'

import { useMemo, useState } from "react"
import Link from "next/link"
import { Plus, RefreshCw } from "lucide-react"
import { cn } from "@/lib/utils"
import type { EdgeNode, NodeCategory, NodeGroup } from "@/lib/types"
import { useNodeInventory } from "@/hooks/use-node-inventory"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog"

const CATEGORY_META: Record<NodeCategory, { label: string; description: string; allowCreate: boolean }> = {
  waiting: {
    label: "待分组",
    description: "新加入的节点会自动出现在此处，可手动迁移到 CDN 或内网穿透分组。",
    allowCreate: false,
  },
  cdn: {
    label: "CDN",
    description: "用于承载 HTTP/HTTPS/WebSocket 业务的边缘节点，可按区域或集群建分组。",
    allowCreate: true,
  },
  tunnel: {
    label: "内网穿透",
    description: "用于 TCP/UDP 隧道代理的节点，通常与业务集群一一对应。",
    allowCreate: true,
  },
}

type GroupedNodes = {
  group: NodeGroup
  nodes: EdgeNode[]
}

export default function EdgeNodesPage() {
  const { groups, nodes, loading, error, reload, createGroup, updateGroup, deleteGroup, moveNode } = useNodeInventory()
  const [category, setCategory] = useState<NodeCategory>("waiting")
  const [creating, setCreating] = useState(false)
  const [newGroupName, setNewGroupName] = useState("")
  const [newGroupDesc, setNewGroupDesc] = useState("")
  const [editingGroup, setEditingGroup] = useState<NodeGroup | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<NodeGroup | null>(null)
  const [pendingAction, setPendingAction] = useState(false)

  const grouped = useMemo(() => {
    const currentGroups = groups.filter((item) => item.category === category)
    const fallbackGroup: NodeGroup | null =
      category === "waiting"
        ? currentGroups.find((item) => item.system) ??
          ({
            id: "group-waiting-default",
            name: "待分组",
            category: "waiting",
            system: true,
          } as NodeGroup)
        : null

    const groupMap = new Map<string, GroupedNodes>()
    currentGroups.forEach((group) => {
      groupMap.set(group.id, { group, nodes: [] })
    })
    if (fallbackGroup && !groupMap.has(fallbackGroup.id)) {
      groupMap.set(fallbackGroup.id, { group: fallbackGroup, nodes: [] })
    }

    nodes
      .filter((node) => node.category === category)
      .forEach((node) => {
        const target = groupMap.get(node.groupId) ?? groupMap.get(fallbackGroup?.id ?? "")
        if (target) {
          target.nodes.push(node)
        }
      })

    return Array.from(groupMap.values()).sort((a, b) => a.group.name.localeCompare(b.group.name, "zh-CN"))
  }, [category, groups, nodes])

  const handleCreateGroup = async () => {
    if (!newGroupName.trim()) return
    try {
      setPendingAction(true)
      await createGroup(category, newGroupName.trim(), newGroupDesc.trim() || undefined)
      setCreating(false)
      setNewGroupName("")
      setNewGroupDesc("")
    } catch (err) {
      console.error("create group failed", err)
    } finally {
      setPendingAction(false)
    }
  }

  const handleUpdateGroup = async () => {
    if (!editingGroup) return
    if (!editingGroup.name.trim()) return
    try {
      setPendingAction(true)
      await updateGroup(editingGroup.id, editingGroup.name.trim(), editingGroup.description?.trim() || undefined)
      setEditingGroup(null)
    } catch (err) {
      console.error("update group failed", err)
    } finally {
      setPendingAction(false)
    }
  }

  const handleDeleteGroup = async () => {
    if (!confirmDelete) return
    try {
      setPendingAction(true)
      await deleteGroup(confirmDelete.id)
      setConfirmDelete(null)
    } catch (err) {
      console.error("delete group failed", err)
    } finally {
      setPendingAction(false)
    }
  }

  const handleMoveNode = async (nodeId: string, targetGroup: string | null) => {
    try {
      setPendingAction(true)
      await moveNode(nodeId, targetGroup)
    } catch (err) {
      console.error("move node failed", err)
    } finally {
      setPendingAction(false)
    }
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">边缘节点</h1>
          <p className="text-sm text-muted-foreground">自动收纳新接入的节点，可在这里进行分组和切换用途。</p>
        </div>
        <Button asChild>
          <Link href="/edge/install">部署新节点</Link>
        </Button>
      </header>

      <div className="flex-1 overflow-auto p-8">
        <Tabs value={category} onValueChange={(value) => setCategory(value as NodeCategory)} className="flex h-full flex-col">
          <TabsList className="w-fit">
            {Object.entries(CATEGORY_META).map(([key, meta]) => (
              <TabsTrigger key={key} value={key}>
                {meta.label}
              </TabsTrigger>
            ))}
          </TabsList>

          {Object.entries(CATEGORY_META).map(([key, meta]) => (
            <TabsContent key={key} value={key}>
              <div className="mt-6 space-y-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">{meta.label}节点</h2>
                    <p className="text-sm text-muted-foreground">{meta.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={reload} disabled={loading}>
                      {loading ? (
                        <>
                          <RefreshCw className="mr-2 h-3.5 w-3.5 animate-spin" />
                          刷新中
                        </>
                      ) : (
                        <>
                          <RefreshCw className="mr-2 h-3.5 w-3.5" />
                          刷新
                        </>
                      )}
                    </Button>
                    {meta.allowCreate ? (
                      <Dialog open={creating} onOpenChange={setCreating}>
                        <DialogTrigger asChild>
                          <Button size="sm">
                            <Plus className="mr-2 h-4 w-4" />
                            新建{meta.label}分组
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>新建{meta.label}分组</DialogTitle>
                          </DialogHeader>
                          <div className="space-y-4">
                            <div>
                              <label className="text-sm font-medium text-foreground">分组名称</label>
                              <Input value={newGroupName} onChange={(event) => setNewGroupName(event.target.value)} />
                            </div>
                            <div>
                              <label className="text-sm font-medium text-foreground">分组描述（可选）</label>
                              <Textarea
                                value={newGroupDesc}
                                onChange={(event) => setNewGroupDesc(event.target.value)}
                                rows={3}
                                placeholder="记录用途、区域等信息"
                              />
                            </div>
                          </div>
                          <DialogFooter>
                            <Button variant="outline" onClick={() => setCreating(false)}>
                              取消
                            </Button>
                            <Button onClick={handleCreateGroup} disabled={!newGroupName.trim() || pendingAction}>
                              创建
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                    ) : null}
                  </div>
                </div>

                {loading && (
                  <Card className="border-border bg-card p-6 text-sm text-muted-foreground">正在加载节点列表…</Card>
                )}

                {error && !loading ? (
                  <Card className="border-destructive/40 bg-destructive/10 p-6 text-sm text-destructive">
                    加载失败：{error}
                  </Card>
                ) : null}

                {!loading && grouped.length === 0 ? (
                  <Card className="border-border bg-muted/30 p-6 text-sm text-muted-foreground">
                    暂无{meta.label}分组，可点击右上角按钮创建。
                  </Card>
                ) : (
                  <div className="grid gap-6">
                    {grouped.map(({ group, nodes: groupNodes }) => (
                      <Card key={group.id} className="border-border bg-card p-6">
                        <div className="flex flex-wrap items-center justify-between gap-4">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <h3 className="text-base font-semibold text-foreground">{group.name}</h3>
                              {group.system ? <Badge variant="secondary">系统</Badge> : null}
                            </div>
                            {group.description ? (
                              <p className="text-sm text-muted-foreground">{group.description}</p>
                            ) : (
                              <p className="text-xs text-muted-foreground">未设置描述</p>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            {!group.system ? (
                              <>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => setEditingGroup({ ...group })}
                                  disabled={pendingAction}
                                >
                                  编辑
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => setConfirmDelete(group)}
                                  disabled={pendingAction}
                                >
                                  删除
                                </Button>
                              </>
                            ) : null}
                          </div>
                        </div>

                        <div className="mt-4 overflow-x-auto">
                          <table className="w-full min-w-[640px] text-sm">
                            <thead className="text-left text-muted-foreground">
                              <tr>
                                <th className="py-2 pr-4 font-medium">节点 ID</th>
                                <th className="py-2 pr-4 font-medium">主机名</th>
                                <th className="py-2 pr-4 font-medium">地址</th>
                                <th className="py-2 pr-4 font-medium">版本</th>
                                <th className="py-2 pr-4 font-medium">最后上报</th>
                                <th className="py-2 font-medium">操作</th>
                              </tr>
                            </thead>
                            <tbody>
                              {groupNodes.length === 0 ? (
                                <tr>
                                  <td colSpan={6} className="py-6 text-center text-sm text-muted-foreground">
                                    当前分组尚无节点
                                  </td>
                                </tr>
                              ) : (
                                groupNodes.map((node) => (
                                  <tr key={node.id} className="border-t border-border/60">
                                    <td className="py-3 pr-4 font-medium text-foreground">{node.id}</td>
                                    <td className="py-3 pr-4 text-muted-foreground">{node.hostname || "—"}</td>
                                    <td className="py-3 pr-4 text-muted-foreground">
                                      {node.addresses.length > 0 ? node.addresses.join(", ") : "—"}
                                    </td>
                                    <td className="py-3 pr-4 text-muted-foreground">{node.version || "—"}</td>
                                    <td className="py-3 pr-4 text-muted-foreground">
                                      {node.lastSeen
                                        ? new Date(node.lastSeen).toLocaleString()
                                        : "未上报"}
                                    </td>
                                    <td className="py-3">
                                      <GroupSelect
                                        category={category}
                                        groups={groups}
                                        value={node.groupId}
                                        systemGroupId={group.system ? group.id : undefined}
                                        loading={pendingAction}
                                        onChange={(value) => handleMoveNode(node.id, value)}
                                      />
                                    </td>
                                  </tr>
                                ))
                              )}
                            </tbody>
                          </table>
                        </div>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            </TabsContent>
          ))}
        </Tabs>
      </div>

      <Dialog open={!!editingGroup} onOpenChange={(open) => !open && setEditingGroup(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>编辑分组</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium text-foreground">分组名称</label>
              <Input
                value={editingGroup?.name ?? ""}
                onChange={(event) => setEditingGroup((prev) => (prev ? { ...prev, name: event.target.value } : prev))}
              />
            </div>
            <div>
              <label className="text-sm font-medium text-foreground">分组描述（可选）</label>
              <Textarea
                rows={3}
                value={editingGroup?.description ?? ""}
                onChange={(event) =>
                  setEditingGroup((prev) => (prev ? { ...prev, description: event.target.value } : prev))
                }
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingGroup(null)}>
              取消
            </Button>
            <Button onClick={handleUpdateGroup} disabled={!editingGroup?.name.trim() || pendingAction}>
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!confirmDelete} onOpenChange={(open) => !open && setConfirmDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确定删除分组 {confirmDelete?.name} 吗？</AlertDialogTitle>
          </AlertDialogHeader>
          <p className="text-sm text-muted-foreground">
            删除后，分组下的节点将自动移动到“待分组”。该操作不可恢复。
          </p>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={pendingAction}>取消</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteGroup} disabled={pendingAction}>
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

interface GroupSelectProps {
  category: NodeCategory
  groups: NodeGroup[]
  value: string
  systemGroupId?: string
  loading?: boolean
  onChange: (groupId: string | null) => void
}

function GroupSelect({ category, groups, value, systemGroupId, loading, onChange }: GroupSelectProps) {
  const options = groups
    .filter((group) => group.category === category)
    .sort((a, b) => a.name.localeCompare(b.name, "zh-CN"))

  const waitingOption =
    category === "waiting"
      ? [
          {
            id: systemGroupId ?? "group-waiting-default",
            name: "待分组",
            system: true,
          },
        ]
      : []

  const merged = [...waitingOption, ...options]

  const handleValueChange = (next: string) => {
    if (!next || next === "default") {
      onChange(null)
    } else {
      onChange(next)
    }
  }

  return (
    <Select value={value || systemGroupId || "default"} onValueChange={handleValueChange} disabled={loading}>
      <SelectTrigger className="w-[200px]">
        <SelectValue placeholder="选择分组" />
      </SelectTrigger>
      <SelectContent>
        {merged.map((group) => (
          <SelectItem key={group.id} value={group.id}>
            <span className={cn(group.system && "text-muted-foreground")}>{group.name}</span>
          </SelectItem>
        ))}
        {category !== "waiting" ? <SelectItem value="default">移至待分组</SelectItem> : null}
      </SelectContent>
    </Select>
  )
}
