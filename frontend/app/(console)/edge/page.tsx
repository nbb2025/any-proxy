import Link from "next/link"
import { redirect } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Search } from "lucide-react"
import { EdgeNodesTable, EdgeNodeSummary } from "@/components/edge/nodes-table"
import { EdgeNodesTabs } from "@/components/edge/nodes-tabs"
import { fetchSnapshot } from "@/lib/api"
import { requireAccessToken } from "@/lib/auth.server"

export default async function EdgeNodesPage() {
  const token = requireAccessToken()
  let snapshot
  try {
    snapshot = await fetchSnapshot(token)
  } catch (error) {
    console.error("[edge] fetch snapshot failed", error)
    redirect("/login")
  }

  const nodeMap = new Map<string, EdgeNodeSummary>()

  snapshot.domains.forEach((domain) => {
    const nodes = domain.edgeNodes.length > 0 ? domain.edgeNodes : ["*"]
    nodes.forEach((nodeId) => {
      const key = nodeId === "*" ? "全局" : nodeId
      if (!nodeMap.has(key)) {
        nodeMap.set(key, { id: key, domains: [], tunnels: [] })
      }
      const entry = nodeMap.get(key)!
      entry.domains.push({ id: domain.id, domain: domain.domain, enableTls: domain.enableTls })
    })
  })

  snapshot.tunnels.forEach((tunnel) => {
    const nodes = tunnel.nodeIds.length > 0 ? tunnel.nodeIds : ["*"]
    nodes.forEach((nodeId) => {
      const key = nodeId === "*" ? "全局" : nodeId
      if (!nodeMap.has(key)) {
        nodeMap.set(key, { id: key, domains: [], tunnels: [] })
      }
      const entry = nodeMap.get(key)!
      entry.tunnels.push({
        id: tunnel.id,
        protocol: tunnel.protocol,
        bindHost: tunnel.bindHost,
        bindPort: tunnel.bindPort,
      })
    })
  })

  const nodes = Array.from(nodeMap.values()).sort((a, b) => a.id.localeCompare(b.id))

  const summary = {
    total: nodes.length,
    withDomains: nodes.filter((node) => node.domains.length > 0 && node.tunnels.length === 0).length,
    withTunnels: nodes.filter((node) => node.tunnels.length > 0 && node.domains.length === 0).length,
    both: nodes.filter((node) => node.domains.length > 0 && node.tunnels.length > 0).length,
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">边缘节点</h1>
          <p className="text-sm text-muted-foreground">汇总域名与隧道引用的节点分布，辅助容量预估。</p>
        </div>
        <Button asChild>
          <Link href="/edge/install">部署新边缘</Link>
        </Button>
      </header>

      <div className="flex-1 space-y-6 overflow-auto p-8">
        <EdgeNodesTabs summary={summary} />

        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="按节点 ID 或域名关键字过滤（暂未接入）" className="pl-10" readOnly />
          </div>
          <Button variant="outline" size="sm" disabled>
            筛选
          </Button>
        </div>

        <EdgeNodesTable nodes={nodes} />
      </div>
    </div>
  )
}
