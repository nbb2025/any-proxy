'use client'

import { useMemo } from "react"
import { formatDistanceToNowStrict } from "date-fns"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { useTunnelInventory } from "@/hooks/use-tunnel-inventory"
import { TunnelGroupsPanel } from "@/components/tunnels/tunnel-groups-panel"
import { TunnelAgentsPanel } from "@/components/tunnels/tunnel-agents-panel"
import type { NodeHeartbeatMap } from "@/components/tunnels/tunnel-groups-panel"

const ONLINE_THRESHOLD_MS = 120_000

export function ProxyTunnelSection() {
  const {
    loading,
    error,
    groups,
    agents,
    nodes,
    reload,
    createGroup,
    updateGroup,
    deleteGroup,
    createAgent,
    updateAgent,
    deleteAgent,
    refreshAgentKey,
  } = useTunnelInventory()

  const nodeStatus = useMemo<NodeHeartbeatMap>(() => {
    const now = Date.now()
    const map: NodeHeartbeatMap = {}
    nodes.forEach((node) => {
      if (!node.id) return
      if (node.lastSeen) {
        const lastSeenMs = new Date(node.lastSeen).getTime()
        map[node.id] = {
          online: now - lastSeenMs <= ONLINE_THRESHOLD_MS,
          lastSeen: node.lastSeen,
        }
      } else {
        map[node.id] = { online: false }
      }
    })
    return map
  }, [nodes])

  const onlineAgents = useMemo(() => agents.filter((agent) => nodeStatus[agent.nodeId]?.online).length, [agents, nodeStatus])
  const onlineEdges = useMemo(() => nodes.filter((node) => node.category !== "waiting" && nodeStatus[node.id]?.online).length, [nodes, nodeStatus])

  const lastHeartbeat = useMemo(() => {
    const timestamps = nodes
      .map((node) => (node.lastSeen ? new Date(node.lastSeen).getTime() : 0))
      .filter((value) => value > 0)
    if (timestamps.length === 0) return null
    const latest = Math.max(...timestamps)
    return formatDistanceToNowStrict(new Date(latest), { addSuffix: true })
  }, [nodes])

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-border text-sm text-muted-foreground">
        正在加载内网穿透拓扑...
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-destructive/40 text-sm text-muted-foreground">
        <p>加载内网穿透数据失败：{error}</p>
        <Button variant="outline" size="sm" onClick={reload}>
          重试
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-sm font-semibold text-foreground">Agent 与节点运行概览</p>
          <p className="text-xs text-muted-foreground">实时统计会话/心跳，帮助定位传输链路健康度。</p>
        </div>
        <Button variant="outline" size="sm" onClick={reload}>
          重新加载
        </Button>
      </div>

      <section className="grid gap-4 md:grid-cols-3">
        <Card className="border-border bg-card p-4">
          <p className="text-sm text-muted-foreground">在线 Agent</p>
          <p className="text-2xl font-semibold text-foreground">
            {onlineAgents}
            <span className="text-base font-normal text-muted-foreground"> / {agents.length}</span>
          </p>
        </Card>
        <Card className="border-border bg-card p-4">
          <p className="text-sm text-muted-foreground">在线 Edge 节点</p>
          <p className="text-2xl font-semibold text-foreground">
            {onlineEdges}
            <span className="text-base font-normal text-muted-foreground">
              {" "}
              / {nodes.filter((node) => node.category !== "waiting").length}
            </span>
          </p>
        </Card>
        <Card className="border-border bg-card p-4">
          <p className="text-sm text-muted-foreground">最近心跳</p>
          <p className="text-2xl font-semibold text-foreground">{lastHeartbeat ?? "暂无上报"}</p>
        </Card>
      </section>

      <TunnelGroupsPanel
        groups={groups}
        nodes={nodes}
        nodeStatus={nodeStatus}
        onCreate={createGroup}
        onUpdate={updateGroup}
        onDelete={deleteGroup}
      />

      <TunnelAgentsPanel
        agents={agents}
        groups={groups}
        nodes={nodes}
        nodeStatus={nodeStatus}
        onCreate={createAgent}
        onUpdate={updateAgent}
        onDelete={deleteAgent}
        onRefreshKey={refreshAgentKey}
      />
    </div>
  )
}
