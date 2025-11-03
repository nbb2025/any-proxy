import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"

export interface EdgeNodeSummary {
  id: string
  domains: { id: string; domain: string; enableTls: boolean }[]
  tunnels: { id: string; protocol: string; bindHost: string; bindPort: number }[]
}

interface EdgeNodesTableProps {
  nodes: EdgeNodeSummary[]
}

export function EdgeNodesTable({ nodes }: EdgeNodesTableProps) {
  if (nodes.length === 0) {
    return (
      <Card className="border-border bg-card p-6 text-sm text-muted-foreground">
        当前没有被引用的边缘节点，可在域名或隧道配置中指定 dgeNodes/
odeIds 来调度。
      </Card>
    )
  }

  return (
    <Card className="border-border bg-card">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">节点 ID</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">域名路由</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">隧道转发</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">协议</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => (
              <tr key={node.id} className="border-b border-border last:border-0 hover:bg-muted/40">
                <td className="px-6 py-4 align-top">
                  <p className="font-medium text-foreground">{node.id}</p>
                  <p className="text-xs text-muted-foreground">
                    被 {node.domains.length} 个域名 / {node.tunnels.length} 条隧道引用
                  </p>
                </td>
                <td className="px-6 py-4 align-top">
                  {node.domains.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {node.domains.map((domain) => (
                        <Badge key={domain.id} variant="outline" className="text-xs">
                          {domain.domain}
                          {domain.enableTls ? " · HTTPS" : ""}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-6 py-4 align-top">
                  {node.tunnels.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {node.tunnels.map((tunnel) => (
                        <Badge key={tunnel.id} variant="secondary" className="text-xs">
                          {tunnel.protocol.toUpperCase()} {tunnel.bindHost}:{tunnel.bindPort}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                  {Array.from(new Set(node.tunnels.map((tunnel) => tunnel.protocol.toUpperCase()))).join(" · ") || "HTTP"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
