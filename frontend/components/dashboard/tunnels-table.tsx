import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import type { TunnelRoute } from "@/lib/types"
import { formatDistanceToNowStrict } from "date-fns"

interface TunnelsTableProps {
  tunnels: TunnelRoute[]
}

const protocolLabels: Record<string, string> = {
  tcp: "TCP",
  udp: "UDP",
  quic: "QUIC",
}

const formatDuration = (value?: number) => {
  if (!value) return "—"
  const seconds = Math.round(value / 1_000_000_000)
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h`
}

export function TunnelsTable({ tunnels }: TunnelsTableProps) {
  if (tunnels.length === 0) {
    return (
      <Card className="border-border bg-card p-6 text-sm text-muted-foreground">
        暂无隧道转发策略，可通过 `/v1/tunnels` 接口下发。
      </Card>
    )
  }

  return (
    <Card className="border-border bg-card">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">监听端口</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">目标服务</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">绑定节点</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">连接策略</th>
              <th className="px-6 py-4 text-left text-sm font-medium text-muted-foreground">更新时间</th>
            </tr>
          </thead>
          <tbody>
            {tunnels.map((tunnel) => (
              <tr key={tunnel.id} className="border-b border-border last:border-0 hover:bg-muted/40">
                <td className="px-6 py-4 align-top">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-foreground">
                        {tunnel.bindHost}:{tunnel.bindPort}
                      </span>
                      <Badge variant="outline">{protocolLabels[tunnel.protocol] ?? tunnel.protocol.toUpperCase()}</Badge>
                      {tunnel.metadata?.enableProxyProtocol ? (
                        <Badge variant="secondary">Proxy Protocol</Badge>
                      ) : null}
                    </div>
                    <p className="text-xs text-muted-foreground">ID: {tunnel.id}</p>
                  </div>
                </td>
                <td className="px-6 py-4 align-top">
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-foreground">{tunnel.target}</p>
                    {tunnel.metadata?.description ? (
                      <p className="text-xs text-muted-foreground">{tunnel.metadata.description}</p>
                    ) : null}
                  </div>
                </td>
                <td className="px-6 py-4 align-top">
                  <div className="flex flex-wrap gap-1">
                    {tunnel.nodeIds.map((node) => (
                      <Badge key={node} variant="outline" className="text-xs">
                        {node}
                      </Badge>
                    ))}
                    {tunnel.nodeIds.length === 0 ? (
                      <span className="text-sm text-muted-foreground">任意节点</span>
                    ) : null}
                  </div>
                </td>
                <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                  空闲断开：{formatDuration(tunnel.idleTimeout)}
                </td>
                <td className="px-6 py-4 align-top text-sm text-muted-foreground">
                  {tunnel.updatedAt ? (
                    formatDistanceToNowStrict(new Date(tunnel.updatedAt), { addSuffix: true })
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
