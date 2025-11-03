import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { DomainRoute } from "@/lib/types"
import { formatDistanceToNowStrict } from "date-fns"

interface DomainsTableProps {
  domains: DomainRoute[]
}

const formatDuration = (value?: number) => {
  if (!value) return "—"
  const seconds = Math.round(value / 1_000_000_000)
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h`
}

export function DomainsTable({ domains }: DomainsTableProps) {
  if (domains.length === 0) {
    return (
      <Card className="border-border bg-card p-6 text-sm text-muted-foreground">
        尚未配置域名转发规则，可通过控制平面 API 的 `/v1/domains` 接口创建。
      </Card>
    )
  }

  return (
    <Card className="border-border bg-card">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">域名</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">关联节点</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">上游服务</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">会话策略</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">更新时间</th>
            </tr>
          </thead>
          <tbody>
            {domains.map((domain) => (
              <tr key={domain.id} className="border-b border-border last:border-0 hover:bg-muted/40">
                <td className="px-6 py-4 align-top">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-foreground">{domain.domain}</span>
                      <Badge variant={domain.enableTls ? "default" : "secondary"}>
                        {domain.enableTls ? "HTTPS" : "HTTP"}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">ID: {domain.id}</p>
                  </div>
                </td>
                <td className="px-6 py-4 align-top">
                  {domain.edgeNodes.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {domain.edgeNodes.map((node) => (
                        <Badge key={node} variant="outline" className="text-xs">
                          {node}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-sm text-muted-foreground">全部边缘节点</span>
                  )}
                </td>
                <td className="px-6 py-4 align-top">
                  <div className="space-y-2">
                    {domain.upstreams.map((upstream) => (
                      <div key={`${domain.id}-${upstream.address}`} className="text-sm">
                        <p className="font-medium text-foreground">{upstream.address}</p>
                        <p className="text-xs text-muted-foreground">
                          权重 {upstream.weight ?? 1}
                          {upstream.failTimeout ? ` · 熔断 ${formatDuration(upstream.failTimeout)}` : ""}
                          {upstream.healthCheck ? ` · 健康检查 ${upstream.healthCheck}` : ""}
                          {upstream.usePersistent ? " · 长连接" : ""}
                        </p>
                      </div>
                    ))}
                  </div>
                </td>
                <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                  {domain.metadata?.sticky ? (
                    <p>开启 Cookie 粘连</p>
                  ) : (
                    <p>无粘连</p>
                  )}
                  <p className="text-xs">
                    连接 {formatDuration(domain.metadata?.timeoutProxy)} · 读取 {formatDuration(domain.metadata?.timeoutRead)} ·
                    发送 {formatDuration(domain.metadata?.timeoutSend)}
                  </p>
                </td>
                <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                  {domain.updatedAt ? (
                    formatDistanceToNowStrict(new Date(domain.updatedAt), { addSuffix: true })
                  ) : (
                    <span className="text-xs">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
