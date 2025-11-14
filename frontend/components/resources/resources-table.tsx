import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { DomainRoute } from "@/lib/types"

interface ResourcesTableProps {
  domains: DomainRoute[]
  pending?: boolean
  onView?: (domain: DomainRoute) => void
  onEdit?: (domain: DomainRoute) => void
  onDelete?: (domain: DomainRoute) => void
}

export function ResourcesTable({ domains, pending, onView, onEdit, onDelete }: ResourcesTableProps) {
  if (domains.length === 0) {
    return (
      <Card className="border-border bg-card p-6 text-sm text-muted-foreground">
        尚未配置域名转发，可通过 `/v1/domains` API 添加路由与上游。
      </Card>
    )
  }

  return (
    <Card className="border-border bg-card">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px]">
          <thead>
            <tr className="border-b border-border">
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">名称</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">请求配置（域名）</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">转发配置</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">备注</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">证书状态</th>
              <th className="px-6 py-4 text-right text-sm font-medium text-muted-foreground">更多</th>
            </tr>
          </thead>
          <tbody>
            {domains.map((domain) => {
              const displayName = domain.metadata?.displayName?.trim() || domain.domain
              const nodeHint =
                domain.edgeNodes.length > 0 ? `绑定 ${domain.edgeNodes.length} 个节点` : "全部节点"
              const upstreamLines = buildUpstreamSummary(domain)
              const inboundSummary = buildListenerSummary(domain.metadata?.inboundListeners)
              const remark = domain.metadata?.remark?.trim() || "—"
              return (
                <tr key={domain.id} className="border-b border-border last:border-0 hover:bg-muted/40">
                  <td className="px-6 py-4 align-top">
                    <div className="space-y-1">
                      <p className="font-medium text-foreground">{displayName}</p>
                      <p className="text-xs text-muted-foreground">ID: {domain.id}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4 align-top">
                    <div className="space-y-1 text-sm">
                      <p className="font-mono text-sm text-foreground">{domain.domain}</p>
                      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <Badge variant={domain.enableTls ? "default" : "secondary"}>
                          {domain.enableTls ? "HTTPS" : "HTTP"}
                        </Badge>
                        <span>{nodeHint}</span>
                      </div>
                      {inboundSummary.length > 0 ? (
                        <p className="text-xs text-muted-foreground">监听：{inboundSummary.join("、")}</p>
                      ) : null}
                    </div>
                  </td>
                  <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                    {upstreamLines.length > 0 ? (
                      upstreamLines.map((line, index) => (
                        <p key={`${domain.id}-${index}`} className="text-foreground">
                          {line}
                        </p>
                      ))
                    ) : (
                      <p>尚未配置上游</p>
                    )}
                  </td>
                  <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                    <p className="text-foreground">{remark}</p>
                    {domain.metadata?.forwardMode === "load_balancing" ? (
                      <p className="text-xs text-muted-foreground">
                        算法：{readableAlgorithm(domain.metadata?.loadBalancingAlgorithm)}
                      </p>
                    ) : null}
                  </td>
                  <td className="px-6 py-4 align-top">
                    <div className="space-y-1 text-sm">
                      <Badge variant={domain.enableTls ? "default" : "outline"}>
                        {domain.enableTls ? "已启用" : "未启用"}
                      </Badge>
                      <p className="text-xs text-muted-foreground">
                        {domain.enableTls ? "证书由控制平面统一下发" : "尚未配置证书"}
                      </p>
                    </div>
                  </td>
                  <td className="px-6 py-4 align-top">
                    <div className="flex items-center justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={pending || !onEdit}
                        onClick={() => onEdit?.(domain)}
                      >
                        编辑
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={pending || !onView}
                        onClick={() => onView?.(domain)}
                      >
                        详情
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={pending || !onDelete}
                        onClick={() => onDelete?.(domain)}
                      >
                        删除
                      </Button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function buildUpstreamSummary(domain: DomainRoute): string[] {
  if (!domain.upstreams || domain.upstreams.length === 0) {
    return []
  }
  const previews = domain.upstreams.slice(0, 2).map((upstream) => {
    const parts = [`${upstream.address}`]
    if (upstream.weight) {
      parts.push(`权重 ${upstream.weight}`)
    }
    return parts.join(" · ")
  })
  if (domain.upstreams.length > 2) {
    previews.push(`…… 等 ${domain.upstreams.length} 条上游`)
  }
  return previews
}

function buildListenerSummary(listeners?: { protocol?: string | null; port?: number | null }[]): string[] {
  if (!listeners || listeners.length === 0) {
    return []
  }
  return listeners.map((listener) => {
    const protocol = listener.protocol || "HTTP"
    const port = listener.port || (protocol === "HTTPS" ? 443 : 80)
    return `${protocol}:${port}`
  })
}

function readableAlgorithm(value?: string): string {
  switch ((value || "").toLowerCase()) {
    case "ip_hash":
      return "IP Hash"
    case "least_conn":
      return "Least Conn"
    default:
      return "轮询"
  }
}
