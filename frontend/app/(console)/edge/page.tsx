'use client'

import { useMemo, useState, useCallback, useEffect } from "react"
import Link from "next/link"
import { ChevronDown, ChevronRight, Plus, RefreshCw } from "lucide-react"
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
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
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

type NodeTab = NodeCategory | "all"

const NODE_TAB_META: Record<NodeTab, { label: string; description: string; allowCreate: boolean }> = {
  all: {
    label: "全部",
    description: "查看所有边缘节点的最新状态，可直接调整分组或重命名。",
    allowCreate: false,
  },
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

const TAB_ORDER: NodeTab[] = ["all", "cdn", "tunnel", "waiting"]

type GroupedNodes = {
  group: NodeGroup
  nodes: EdgeNode[]
}

export default function EdgeNodesPage() {
  const {
    groups,
    nodes,
    loading,
    error,
    reload,
    createGroup,
    updateGroup,
    deleteGroup,
    moveNode,
    changeNodeCategory,
    deleteNode,
    setDesiredVersion,
    setDesiredVersionBulk,
    agentVersions,
    latestResolvedVersion,
  } = useNodeInventory()
  const [category, setCategory] = useState<NodeTab>("all")
  const [creating, setCreating] = useState(false)
  const [newGroupName, setNewGroupName] = useState("")
  const [newGroupDesc, setNewGroupDesc] = useState("")
  const [editingGroup, setEditingGroup] = useState<NodeGroup | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<NodeGroup | null>(null)
  const [pendingAction, setPendingAction] = useState(false)
  const [categoryDialogNode, setCategoryDialogNode] = useState<EdgeNode | null>(null)
  const [categorySelection, setCategorySelection] = useState<NodeCategory>("cdn")
  const [groupDialogNode, setGroupDialogNode] = useState<EdgeNode | null>(null)
  const [groupSelection, setGroupSelection] = useState<string>("")
  const [deleteNodeTarget, setDeleteNodeTarget] = useState<EdgeNode | null>(null)
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({})
  const CLEAR_VERSION_OPTION = "__clear__"
  const [versionDialogNode, setVersionDialogNode] = useState<EdgeNode | null>(null)
  const [versionInput, setVersionInput] = useState(CLEAR_VERSION_OPTION)
  const [versionPending, setVersionPending] = useState(false)

  const groupedMap = useMemo<Record<NodeCategory, GroupedNodes[]>>(() => {
    const categories: NodeCategory[] = ["waiting", "cdn", "tunnel"]
    const result: Record<NodeCategory, GroupedNodes[]> = {
      waiting: [],
      cdn: [],
      tunnel: [],
    }

    categories.forEach((cat) => {
      const currentGroups = groups.filter((item) => item.category === cat)
      const fallbackGroup: NodeGroup | null =
        cat === "waiting"
          ? currentGroups.find((item) => item.system) ??
            ({
              id: "group-waiting-default",
              name: "待分组",
              category: "waiting",
              system: true,
            } as NodeGroup)
          : null

      const map = new Map<string, GroupedNodes>()
      currentGroups.forEach((group) => {
        map.set(group.id, { group, nodes: [] })
      })
      if (fallbackGroup && !map.has(fallbackGroup.id)) {
        map.set(fallbackGroup.id, { group: fallbackGroup, nodes: [] })
      }

      nodes
        .filter((node) => node.category === cat)
        .forEach((node) => {
          const target = map.get(node.groupId) ?? map.get(fallbackGroup?.id ?? "")
          if (target) {
            target.nodes.push(node)
          }
        })

      result[cat] = Array.from(map.values()).sort((a, b) => a.group.name.localeCompare(b.group.name, "zh-CN"))
    })

    return result
  }, [groups, nodes])

  const grouped = useMemo(() => {
    if (category === "all") {
      return []
    }
    return groupedMap[category]
  }, [category, groupedMap])

  const systemGroupMap = useMemo<Record<NodeCategory, string | undefined>>(() => {
    const map: Record<NodeCategory, string | undefined> = {
      waiting: undefined,
      cdn: undefined,
      tunnel: undefined,
    }
    groups.forEach((group) => {
      if (group.system) {
        map[group.category] = group.id
      }
    })
    return map
  }, [groups])

  const allNodes = useMemo(() => {
    return [...nodes].sort((a, b) => {
      const aTime = a.lastSeen ? new Date(a.lastSeen).getTime() : 0
      const bTime = b.lastSeen ? new Date(b.lastSeen).getTime() : 0
      return bTime - aTime
    })
  }, [nodes])

  const [selectedMap, setSelectedMap] = useState<Record<string, boolean>>({})
  useEffect(() => {
    setSelectedMap((prev) => {
      const next: Record<string, boolean> = {}
      nodes.forEach((node) => {
        if (prev[node.id]) {
          next[node.id] = true
        }
      })
      return next
    })
  }, [nodes])

  const selectedIds = useMemo(() => Object.keys(selectedMap).filter((id) => selectedMap[id]), [selectedMap])
  const selectedCount = selectedIds.length
  const hasSelection = selectedCount > 0

  const toggleSelectNode = useCallback((nodeId: string, checked: boolean) => {
    setSelectedMap((prev) => {
      const next = { ...prev }
      if (checked) {
        next[nodeId] = true
      } else {
        delete next[nodeId]
      }
      return next
    })
  }, [])

  const selectNodes = useCallback((nodeList: EdgeNode[], checked: boolean) => {
    setSelectedMap((prev) => {
      const next = { ...prev }
      nodeList.forEach((node) => {
        if (checked) {
          next[node.id] = true
        } else {
          delete next[node.id]
        }
      })
      return next
    })
  }, [])

  const clearSelection = useCallback(() => {
    setSelectedMap({})
  }, [])

  const [bulkVersionDialogOpen, setBulkVersionDialogOpen] = useState(false)
  const [bulkVersionValue, setBulkVersionValue] = useState(CLEAR_VERSION_OPTION)
  const [bulkVersionPending, setBulkVersionPending] = useState(false)
  useEffect(() => {
    if (!hasSelection && bulkVersionDialogOpen) {
      setBulkVersionDialogOpen(false)
      setBulkVersionValue(CLEAR_VERSION_OPTION)
    }
  }, [bulkVersionDialogOpen, hasSelection])

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

  const toggleRow = (nodeId: string) => {
    setExpandedRows((prev) => ({
      ...prev,
      [nodeId]: !prev[nodeId],
    }))
  }

  const baseVersionChoices = useMemo(() => {
    const seen = new Set<string>()
    const list: string[] = []
    const add = (value?: string | null) => {
      const trimmed = value?.trim()
      if (!trimmed || seen.has(trimmed)) {
        return
      }
      seen.add(trimmed)
      list.push(trimmed)
    }
    add("latest")
    agentVersions.forEach((item) => add(item))
    return list
  }, [agentVersions])

  const latestDisplayName = latestResolvedVersion
    ? `latest（指向 ${latestResolvedVersion}）`
    : "latest"

  const singleVersionChoices = useMemo(() => {
    const seen = new Set(baseVersionChoices)
    const list = [...baseVersionChoices]
    if (versionDialogNode) {
      const extras = [versionDialogNode.agentDesiredVersion, versionDialogNode.agentVersion]
      extras.forEach((value) => {
        const trimmed = value?.trim()
        if (trimmed && !seen.has(trimmed)) {
          seen.add(trimmed)
          list.push(trimmed)
        }
      })
    }
    return list
  }, [baseVersionChoices, versionDialogNode])

  const openVersionDialog = useCallback((node: EdgeNode) => {
    setVersionDialogNode(node)
    setVersionInput(node.agentDesiredVersion || CLEAR_VERSION_OPTION)
  }, [])

  const handleVersionSubmit = useCallback(async () => {
    if (!versionDialogNode) return
    try {
      setVersionPending(true)
      const desiredValue = versionInput === CLEAR_VERSION_OPTION ? "" : versionInput.trim()
      await setDesiredVersion(versionDialogNode.id, desiredValue.length > 0 ? desiredValue : null)
      setVersionDialogNode(null)
      setVersionInput(CLEAR_VERSION_OPTION)
    } catch (err) {
      console.error("set desired version failed", err)
    } finally {
      setVersionPending(false)
    }
  }, [setDesiredVersion, versionDialogNode, versionInput])

  const handleBulkVersionSubmit = useCallback(async () => {
    if (selectedIds.length === 0) return
    try {
      setBulkVersionPending(true)
      const desiredValue = bulkVersionValue === CLEAR_VERSION_OPTION ? "" : bulkVersionValue.trim()
      await setDesiredVersionBulk(selectedIds, desiredValue.length > 0 ? desiredValue : null)
      setBulkVersionDialogOpen(false)
      setBulkVersionValue(CLEAR_VERSION_OPTION)
      clearSelection()
    } catch (err) {
      console.error("set desired version (bulk) failed", err)
    } finally {
      setBulkVersionPending(false)
    }
  }, [bulkVersionValue, clearSelection, selectedIds, setDesiredVersionBulk])

  const openCategoryDialog = (node: EdgeNode) => {
    setCategoryDialogNode(node)
    setCategorySelection(node.category)
  }

  const handleChangeCategory = async () => {
    if (!categoryDialogNode) return
    try {
      setPendingAction(true)
      await changeNodeCategory(categoryDialogNode.id, categorySelection)
      setCategoryDialogNode(null)
    } catch (err) {
      console.error("change category failed", err)
    } finally {
      setPendingAction(false)
    }
  }

  const openGroupDialog = (node: EdgeNode) => {
    setGroupDialogNode(node)
    setGroupSelection(node.groupId || systemGroupMap[node.category] || "default")
  }

  const handleMoveNodeConfirm = async () => {
    if (!groupDialogNode) return
    try {
      setPendingAction(true)
      const target = groupSelection === "default" ? null : groupSelection
      await moveNode(groupDialogNode.id, target)
      setGroupDialogNode(null)
      setGroupSelection("")
    } catch (err) {
      console.error("move node failed", err)
    } finally {
      setPendingAction(false)
    }
  }

  const handleDeleteNode = async () => {
    if (!deleteNodeTarget) return
    try {
      setPendingAction(true)
      await deleteNode(deleteNodeTarget.id)
      setDeleteNodeTarget(null)
    } catch (err) {
      console.error("delete node failed", err)
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
        <Tabs value={category} onValueChange={(value) => setCategory(value as NodeTab)} className="flex h-full flex-col">
          <TabsList className="flex w-fit flex-wrap gap-2">
            {TAB_ORDER.map((key) => (
              <TabsTrigger key={key} value={key}>
                {NODE_TAB_META[key].label}
              </TabsTrigger>
            ))}
          </TabsList>

          {TAB_ORDER.map((value) => {
            const meta = NODE_TAB_META[value]
        if (value === "all") {
          const visibleSelectedCount = allNodes.filter((node) => selectedMap[node.id]).length
          const allVisibleSelected = allNodes.length > 0 && visibleSelectedCount === allNodes.length
          const someVisibleSelected = visibleSelectedCount > 0 && !allVisibleSelected
          const checkAllState = allVisibleSelected ? true : someVisibleSelected ? "indeterminate" : false

          return (
            <TabsContent key={value} value={value}>
              <div className="mt-6 space-y-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">{meta.label}节点</h2>
                    <p className="text-sm text-muted-foreground">{meta.description}</p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {hasSelection ? <Badge variant="secondary">{selectedCount} 个已选</Badge> : null}
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
                    <Button size="sm" disabled={!hasSelection} onClick={() => setBulkVersionDialogOpen(true)}>
                      批量设置版本
                    </Button>
                    <Button variant="ghost" size="sm" disabled={!hasSelection} onClick={clearSelection}>
                      清除选择
                    </Button>
                  </div>
                </div>

                {error && category === "all" && !loading ? (
                  <Card className="border-destructive/40 bg-destructive/10 p-6 text-sm text-destructive">
                    加载失败：{error}
                      </Card>
                    ) : null}

                    <Card className="border-border bg-card">
                      <div className="overflow-x-auto">
                        <table className="w-full min-w-[720px] text-sm">
                          <thead className="text-left text-muted-foreground">
                            <tr>
                              <th className="w-10">
                                <Checkbox
                                  checked={checkAllState}
                                  onCheckedChange={(checked) => selectNodes(allNodes, checked === true)}
                                  aria-label="全选节点"
                                />
                              </th>
                              <th className="w-10" aria-hidden="true" />
                              <th className="py-2 pr-4 font-medium">显示名称</th>
                              <th className="py-2 pr-4 font-medium">用途</th>
                              <th className="py-2 pr-4 font-medium">地址</th>
                              <th className="py-2 pr-4 font-medium">Agent 版本</th>
                              <th className="py-2 pr-4 font-medium">最后上报</th>
                              <th className="py-2 pr-4 font-medium">操作</th>
                            </tr>
                          </thead>
                          <tbody>
                            {allNodes.length === 0 ? (
                              <tr>
                                <td colSpan={8} className="py-6 text-center text-sm text-muted-foreground">
                                  暂无边缘节点，可前往「部署新节点」生成安装命令。
                                </td>
                              </tr>
                            ) : (
                              allNodes.map((node) => (
                              <NodeRow
                                key={node.id}
                                node={node}
                                groups={groups}
                                systemGroupId={systemGroupMap[node.category]}
                                latestResolvedVersion={latestResolvedVersion}
                                pending={pendingAction}
                                showCategory
                                selectable
                                selected={!!selectedMap[node.id]}
                                onSelectChange={(checked) => toggleSelectNode(node.id, checked)}
                                expanded={!!expandedRows[node.id]}
                                onToggle={() => toggleRow(node.id)}
                                onRequestCategory={openCategoryDialog}
                                onRequestMove={openGroupDialog}
                                onRequestVersion={openVersionDialog}
                                onDelete={(node) => setDeleteNodeTarget(node)}
                              />
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  </div>
                </TabsContent>
              )
            }

            const catKey = value as NodeCategory
            const categoryMeta = CATEGORY_META[catKey]
            const categoryGroups = groupedMap[catKey]

            return (
              <TabsContent key={value} value={value}>
                <div className="mt-6 space-y-6">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h2 className="text-lg font-semibold text-foreground">{categoryMeta.label}节点</h2>
                      <p className="text-sm text-muted-foreground">{categoryMeta.description}</p>
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
                      {categoryMeta.allowCreate ? (
                        <Dialog open={creating} onOpenChange={setCreating}>
                          <DialogTrigger asChild>
                            <Button size="sm">
                              <Plus className="mr-2 h-4 w-4" />
                              新建{categoryMeta.label}分组
                            </Button>
                          </DialogTrigger>
                          <DialogContent>
                            <DialogHeader>
                              <DialogTitle>新建{categoryMeta.label}分组</DialogTitle>
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

                  {error && category === value && !loading ? (
                    <Card className="border-destructive/40 bg-destructive/10 p-6 text-sm text-destructive">
                      加载失败：{error}
                    </Card>
                  ) : null}

                  {loading && category === value ? (
                    <Card className="border-border bg-card p-6 text-sm text-muted-foreground">正在加载节点列表…</Card>
                  ) : categoryGroups.length === 0 ? (
                    <Card className="border-border bg-muted/30 p-6 text-sm text-muted-foreground">
                      暂无{categoryMeta.label}分组，可点击右上角按钮创建。
                    </Card>
                  ) : (
                    <div className="space-y-6">
                      {categoryGroups.map(({ group, nodes: groupNodes }) => (
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
                                  <th className="w-10" aria-hidden="true" />
                                  <th className="py-2 pr-4 font-medium">显示名称</th>
                                  <th className="py-2 pr-4 font-medium">地址</th>
                                  <th className="py-2 pr-4 font-medium">Agent 版本</th>
                                  <th className="py-2 pr-4 font-medium">最后上报</th>
                                  <th className="py-2 pr-4 font-medium">操作</th>
                                </tr>
                              </thead>
                              <tbody>
                                {groupNodes.length === 0 ? (
                                  <tr>
                                    <td colSpan={7} className="py-6 text-center text-sm text-muted-foreground">
                                      当前分组尚无节点
                                    </td>
                                  </tr>
                                ) : (
                                  groupNodes.map((node) => (
                                    <NodeRow
                                      key={node.id}
                                      node={node}
                                      groups={groups}
                                      systemGroupId={group.system ? group.id : systemGroupMap[node.category]}
                                      latestResolvedVersion={latestResolvedVersion}
                                      pending={pendingAction}
                                      expanded={!!expandedRows[node.id]}
                                      onToggle={() => toggleRow(node.id)}
                                      onRequestCategory={openCategoryDialog}
                                      onRequestMove={openGroupDialog}
                                      onRequestVersion={openVersionDialog}
                                      onDelete={(node) => setDeleteNodeTarget(node)}
                                    />
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
            )
          })}
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

      <Dialog open={!!versionDialogNode} onOpenChange={(open) => {
        if (!open) {
          setVersionDialogNode(null)
          setVersionInput(CLEAR_VERSION_OPTION)
        }
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>设置 Agent 目标版本</DialogTitle>
            <DialogDescription>节点 {versionDialogNode?.id}</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="agent-version">目标版本</Label>
              <Select value={versionInput} onValueChange={(value) => setVersionInput(value)}>
                <SelectTrigger id="agent-version">
                  <SelectValue placeholder="选择目标版本（留空清除）" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={CLEAR_VERSION_OPTION}>清除目标版本</SelectItem>
                  {singleVersionChoices.map((version) => (
                    <SelectItem key={version} value={version}>
                      {version === "latest" ? latestDisplayName : version}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                当前运行：{resolveAgentVersionLabel(versionDialogNode?.agentVersion, latestResolvedVersion) || "未知"}
              </p>
            </div>
            <p className="text-xs text-muted-foreground">
              设置后，节点会主动下载对应版本的二进制并自动重启。
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setVersionDialogNode(null)
                setVersionInput(CLEAR_VERSION_OPTION)
              }}
              disabled={versionPending}
            >
              取消
            </Button>
            <Button onClick={handleVersionSubmit} disabled={versionPending}>
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={bulkVersionDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            setBulkVersionDialogOpen(false)
            setBulkVersionValue("")
          } else if (hasSelection) {
            setBulkVersionDialogOpen(true)
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>批量设置 Agent 目标版本</DialogTitle>
            <DialogDescription>已选择 {selectedCount} 个节点</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="bulk-agent-version">目标版本</Label>
              <Select value={bulkVersionValue} onValueChange={(value) => setBulkVersionValue(value)}>
                <SelectTrigger id="bulk-agent-version">
                  <SelectValue placeholder="选择目标版本（留空清除）" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={CLEAR_VERSION_OPTION}>清除目标版本</SelectItem>
                  {baseVersionChoices.map((version) => (
                    <SelectItem key={version} value={version}>
                      {version === "latest" ? latestDisplayName : version}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <p className="text-xs text-muted-foreground">
              仅会对选中的节点写入目标版本，未选节点保持现状。可随时清空以恢复手动控制。
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setBulkVersionDialogOpen(false)
                setBulkVersionValue(CLEAR_VERSION_OPTION)
              }}
              disabled={bulkVersionPending}
            >
              取消
            </Button>
            <Button onClick={handleBulkVersionSubmit} disabled={bulkVersionPending || !hasSelection}>
              下发版本
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!categoryDialogNode} onOpenChange={(open) => !open && setCategoryDialogNode(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>修改节点用途</DialogTitle>
            <p className="text-sm text-muted-foreground">{categoryDialogNode?.id}</p>
          </DialogHeader>
          <div className="space-y-2">
            <Select
              value={categorySelection}
              onValueChange={(value) => setCategorySelection(value as NodeCategory)}
              disabled={pendingAction}
            >
              <SelectTrigger>
                <SelectValue placeholder="选择用途" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="cdn">CDN 节点</SelectItem>
                <SelectItem value="tunnel">内网穿透节点</SelectItem>
                <SelectItem value="waiting">待分组</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">修改用途后，节点会自动移动到对应用途的系统分组。</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCategoryDialogNode(null)}>
              取消
            </Button>
            <Button onClick={handleChangeCategory} disabled={pendingAction}>
              确认修改
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!groupDialogNode} onOpenChange={(open) => !open && setGroupDialogNode(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>移动分组</DialogTitle>
            <p className="text-sm text-muted-foreground">{groupDialogNode?.id}</p>
          </DialogHeader>
          <div className="space-y-2">
            <Select
              value={groupSelection || "default"}
              onValueChange={(value) => setGroupSelection(value)}
              disabled={pendingAction}
            >
              <SelectTrigger>
                <SelectValue placeholder="选择分组" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">待分组</SelectItem>
                {groups
                  .filter((group) => group.category === groupDialogNode?.category)
                  .map((group) => (
                    <SelectItem key={group.id} value={group.id}>
                      {group.name}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGroupDialogNode(null)}>
              取消
            </Button>
            <Button onClick={handleMoveNodeConfirm} disabled={pendingAction}>
              确认移动
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteNodeTarget} onOpenChange={(open) => !open && setDeleteNodeTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除节点 {deleteNodeTarget?.id} 吗？</AlertDialogTitle>
            <AlertDialogDescription>
              删除后客户端将无法再使用旧 Key 连接，除非重新部署并申请新的节点 Key。该操作不可恢复。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={pendingAction}>取消</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteNode} disabled={pendingAction}>
              删除节点
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

interface NodeRowProps {
  node: EdgeNode
  groups: NodeGroup[]
  systemGroupId?: string
  latestResolvedVersion?: string
  pending?: boolean
  showCategory?: boolean
  selectable?: boolean
  selected?: boolean
  onSelectChange?: (checked: boolean) => void
  expanded: boolean
  onToggle: () => void
  onRequestCategory: (node: EdgeNode) => void
  onRequestMove: (node: EdgeNode) => void
  onDelete: (node: EdgeNode) => void
  onRequestVersion: (node: EdgeNode) => void
}

function NodeRow({
  node,
  groups,
  systemGroupId,
  latestResolvedVersion,
  pending,
  showCategory,
  selectable,
  selected,
  onSelectChange,
  expanded,
  onToggle,
  onRequestCategory,
  onRequestMove,
  onRequestVersion,
  onDelete,
}: NodeRowProps) {
  const lastSeen = node.lastSeen ? new Date(node.lastSeen).toLocaleString() : "未上报"
  const baseColumns = 6 // expand, name, address, version, last seen, actions
  const selectionOffset = selectable ? 1 : 0
  const categoryOffset = showCategory ? 1 : 0
  const detailColSpan = baseColumns + selectionOffset + categoryOffset
  const displayName = node.name?.trim() || node.id

  return (
    <>
      <tr className="border-t border-border/60">
        {selectable ? (
          <td className="py-3 pr-2 align-top">
            <Checkbox
              checked={selected}
              onCheckedChange={(checked) => onSelectChange?.(checked === true)}
              aria-label="选择节点"
            />
          </td>
        ) : null}
        <td className="py-3 pr-2">
          <Button variant="ghost" size="icon" className="h-8 w-8 text-muted-foreground" onClick={onToggle}>
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
        </td>
        <td className="py-3 pr-4 font-medium text-foreground">{displayName}</td>
        {showCategory ? (
          <td className="py-3 pr-4">
            <Badge variant="outline">{CATEGORY_META[node.category].label}</Badge>
          </td>
        ) : null}
        <td className="py-3 pr-4 text-muted-foreground">
          <AddressColumn addresses={node.addresses} />
        </td>
        <td className="py-3 pr-4 text-muted-foreground">
          <AgentVersionCell node={node} latestResolvedVersion={latestResolvedVersion} />
        </td>
        <td className="py-3 pr-4 text-muted-foreground">{lastSeen}</td>
        <td className="py-3 pr-4">
          <div className="flex flex-col gap-2">
            <Button variant="outline" size="sm" disabled={pending} onClick={() => onRequestCategory(node)}>
              修改用途
            </Button>
            <Button variant="outline" size="sm" disabled={pending} onClick={() => onRequestMove(node)}>
              移动分组
            </Button>
            <Button variant="outline" size="sm" disabled={pending} onClick={() => onRequestVersion(node)}>
              设置版本
            </Button>
            <Button variant="destructive" size="sm" disabled={pending} onClick={() => onDelete(node)}>
              删除
            </Button>
          </div>
        </td>
      </tr>
      <tr className={cn(!expanded && "hidden")}>
        <td colSpan={detailColSpan} className="bg-muted/30 p-3">
          <NodeExtraDetails node={node} latestResolvedVersion={latestResolvedVersion} />
        </td>
      </tr>
    </>
  )
}

function AddressColumn({ addresses }: { addresses: string[] }) {
  if (!addresses || addresses.length === 0) {
    return <>—</>
  }
  const { internal, external } = splitAddresses(addresses)
  return (
    <div className="space-y-1 text-xs text-muted-foreground">
      {external.length > 0 ? (
        <div>
          <span className="text-muted-foreground/70">公网</span>
          <div className="text-foreground">{external.join(", ")}</div>
        </div>
      ) : null}
      {internal.length > 0 ? (
        <div>
          <span className="text-muted-foreground/70">内网</span>
          <div className="text-foreground">{internal.join(", ")}</div>
        </div>
      ) : null}
      {external.length === 0 && internal.length === 0 ? <span>—</span> : null}
    </div>
  )
}

function AgentVersionCell({ node, latestResolvedVersion }: { node: EdgeNode; latestResolvedVersion?: string }) {
  const currentRaw = node.agentVersion?.trim()
  const current = resolveAgentVersionLabel(currentRaw, latestResolvedVersion)
  const desired = node.agentDesiredVersion?.trim()
  return (
    <div className="space-y-1 text-xs">
      <p className="font-medium text-foreground">{current || "未知"}</p>
      {desired ? (
        desired === currentRaw ? (
          <Badge variant="outline">已同步</Badge>
        ) : (
          <Badge variant="secondary">目标 {formatDesiredLabel(desired, latestResolvedVersion)}</Badge>
        )
      ) : null}
    </div>
  )
}

function resolveAgentVersionLabel(value?: string | null, latestResolved?: string): string {
  const trimmed = value?.trim()
  if (!trimmed) {
    return ""
  }
  const resolved = latestResolved?.trim()
  if (trimmed === "latest" && resolved) {
    return resolved
  }
  return trimmed
}

function formatDesiredLabel(value: string, latestResolved?: string): string {
  if (value === "latest" && latestResolved) {
    return `latest → ${latestResolved}`
  }
  return value
}

function NodeExtraDetails({ node, latestResolvedVersion }: { node: EdgeNode; latestResolvedVersion?: string }) {
  const lastUpgrade = node.lastUpgradeAt ? new Date(node.lastUpgradeAt).toLocaleString() : "—"
  const currentVersion = resolveAgentVersionLabel(node.agentVersion, latestResolvedVersion) || "—"
  const desiredVersion = node.agentDesiredVersion
    ? formatDesiredLabel(node.agentDesiredVersion, latestResolvedVersion)
    : "—"
  return (
    <div className="grid gap-4 text-sm text-muted-foreground md:grid-cols-6">
      <div>
        <p className="text-xs uppercase text-muted-foreground/70">节点 ID</p>
        <p className="font-mono text-foreground">{node.id}</p>
      </div>
      <div>
        <p className="text-xs uppercase text-muted-foreground/70">主机名</p>
        <p className="font-medium text-foreground">{node.hostname || "—"}</p>
      </div>
      <div>
        <p className="text-xs uppercase text-muted-foreground/70">Go 版本</p>
        <p className="font-medium text-foreground">{node.version || "—"}</p>
      </div>
      <div>
        <p className="text-xs uppercase text-muted-foreground/70">Agent 版本</p>
        <p className="font-medium text-foreground">{currentVersion}</p>
      </div>
      <div>
        <p className="text-xs uppercase text-muted-foreground/70">目标版本</p>
        <p className="font-medium text-foreground">{desiredVersion}</p>
      </div>
      <div>
        <p className="text-xs uppercase text-muted-foreground/70">最近升级</p>
        <p className="font-medium text-foreground">{lastUpgrade}</p>
      </div>
      <div>
        <p className="text-xs uppercase text-muted-foreground/70">注册时间</p>
        <p className="font-medium text-foreground">{node.createdAt ? new Date(node.createdAt).toLocaleString() : "—"}</p>
      </div>
    </div>
  )
}

function splitAddresses(addresses: string[]) {
  const internal: string[] = []
  const external: string[] = []
  addresses.forEach((addr) => {
    const trimmed = addr.trim()
    if (!trimmed) {
      return
    }
    if (isPrivateAddress(trimmed)) {
      internal.push(trimmed)
    } else {
      external.push(trimmed)
    }
  })
  return { internal, external }
}

function isPrivateAddress(address: string): boolean {
  const lower = address.toLowerCase()
  if (lower.startsWith("10.")) return true
  if (lower.startsWith("192.168.")) return true
  if (lower.startsWith("169.254.")) return true
  if (lower.startsWith("127.")) return true
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true
  if (lower.startsWith("fe80") || lower.startsWith("::1")) return true
  if (lower.startsWith("172.")) {
    const parts = lower.split(".")
    if (parts.length >= 2) {
      const second = Number(parts[1])
      if (second >= 16 && second <= 31) {
        return true
      }
    }
  }
  return false
}
