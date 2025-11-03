import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { DomainRoute } from "@/lib/types"

interface ResourcesTableProps {
  domains: DomainRoute[]
}

export function ResourcesTable({ domains }: ResourcesTableProps) {
  if (domains.length === 0) {
    return (
      <Card className="border-border bg-card p-6 text-sm text-muted-foreground">
        尚未配置域名转发，可通过 `/v1/domains` API 添加路由与上游。
      </Card>
    )
  }

  const rows = domains.flatMap((domain) =>
    domain.upstreams.map((upstream) => ({
      domain,
      upstream,
    })),
  )

  return (
    <Card className="border-border bg-card">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">域名</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">上游地址</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">调度属性</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">健康检查</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ domain, upstream }) => (
              <tr key={`${domain.id}-${upstream.address}`} className="border-b border-border last:border-0 hover:bg-muted/40">
                <td className="px-6 py-4 align-top">
                  <div className="space-y-1">
                    <p className="font-medium text-foreground">{domain.domain}</p>
                    <div className="flex flex-wrap gap-1 text-xs text-muted-foreground">
                      <Badge variant={domain.enableTls ? "default" : "secondary"}>
                        {domain.enableTls ? "HTTPS" : "HTTP"}
                      </Badge>
                      {domain.edgeNodes.length > 0 ? (
                        <span>节点 {domain.edgeNodes.join(", ")}</span>
                      ) : (
                        <span>全局节点</span>
                      )}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 align-top">
                  <p className="text-sm font-medium text-foreground">{upstream.address}</p>
                  <p className="text-xs text-muted-foreground">权重 {upstream.weight ?? 1}</p>
                </td>
                <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                  {upstream.usePersistent ? <p>启用长连接</p> : <p>短连接</p>}
                  {upstream.maxFails ? <p>最大失败 {upstream.maxFails} 次</p> : null}
                  {upstream.failTimeout ? <p>熔断 {Math.round((upstream.failTimeout ?? 0) / 1_000_000_000)}s</p> : null}
                </td>
                <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                  {upstream.healthCheck ?? "未配置"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
