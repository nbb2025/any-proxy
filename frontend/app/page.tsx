import { Button } from "@/components/ui/button"
import { RefreshCcw } from "lucide-react"
import { DashboardMetrics } from "@/components/dashboard/metrics"
import { DomainsTable } from "@/components/dashboard/domains-table"
import { TunnelsTable } from "@/components/dashboard/tunnels-table"
import { fetchSnapshot } from "@/lib/api"

export default async function DashboardPage() {
  const snapshot = await fetchSnapshot()

  const totalDomains = snapshot.domains.length
  const tlsEnabled = snapshot.domains.filter((domain) => domain.enableTls).length
  const upstreamTotal = snapshot.domains.reduce((sum, domain) => sum + domain.upstreams.length, 0)
  const uniqueNodes = new Set<string>()
  snapshot.domains.forEach((domain) => domain.edgeNodes.forEach((node) => uniqueNodes.add(node)))
  snapshot.tunnels.forEach((tunnel) => tunnel.nodeIds.forEach((node) => uniqueNodes.add(node)))

  const totalTunnels = snapshot.tunnels.length
  const tunnelProtocols = new Set(snapshot.tunnels.map((item) => item.protocol.toUpperCase()))

  const metrics = [
    {
      label: "域名路由",
      value: String(totalDomains),
      description: `${tlsEnabled} 个启用 HTTPS` + (totalDomains > 0 ? ` · ${upstreamTotal} 条上游` : ""),
    },
    {
      label: "隧道转发",
      value: String(totalTunnels),
      description:
        totalTunnels > 0 ? `${Array.from(tunnelProtocols).join(" · ")} 协议` : "暂未配置", 
    },
    {
      label: "节点覆盖",
      value: String(uniqueNodes.size),
      description: uniqueNodes.size > 0 ? `域名 / 隧道共同覆盖 ${uniqueNodes.size} 个节点` : "全部节点自动接入",
    },
    {
      label: "最新快照",
      value: new Date(snapshot.generatedAt).toLocaleTimeString("zh-CN", { hour12: false }),
      description: "控制平面已下发的最新版本时间",
    },
  ]

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">控制台</h1>
          <p className="text-sm text-muted-foreground">概览域名、隧道与节点的最新分发情况。</p>
        </div>
        <Button variant="outline" size="sm" asChild>
          <a href="/">
            <RefreshCcw className="mr-2 h-4 w-4" /> 刷新页面
          </a>
        </Button>
      </header>

      <div className="flex-1 space-y-6 overflow-auto p-8">
        <DashboardMetrics metrics={metrics} version={snapshot.version} generatedAt={snapshot.generatedAt} />

        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">域名转发</h2>
            <p className="text-xs text-muted-foreground">数据来源：/v1/domains</p>
          </div>
          <DomainsTable domains={snapshot.domains} />
        </section>

        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">隧道穿透</h2>
            <p className="text-xs text-muted-foreground">数据来源：/v1/tunnels</p>
          </div>
          <TunnelsTable tunnels={snapshot.tunnels} />
        </section>
      </div>
    </div>
  )
}
