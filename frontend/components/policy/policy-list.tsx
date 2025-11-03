import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { MoreHorizontal, Network, Clock } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import type { TunnelRoute } from "@/lib/types"
import { formatDistanceToNowStrict } from "date-fns"

interface PolicyListProps {
  tunnels: TunnelRoute[]
}

export function PolicyList({ tunnels }: PolicyListProps) {
  if (tunnels.length === 0) {
    return (
      <Card className="border-border bg-card p-6 text-sm text-muted-foreground">
        暂无隧道配置。
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {tunnels.map((tunnel) => (
        <Card key={tunnel.id} className="border-border bg-card p-6">
          <div className="space-y-4">
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-semibold text-foreground">
                    {tunnel.bindHost}:{tunnel.bindPort} → {tunnel.target}
                  </h3>
                  <Badge variant="secondary">{tunnel.protocol.toUpperCase()}</Badge>
                  {tunnel.metadata?.enableProxyProtocol ? <Badge variant="outline">Proxy Protocol</Badge> : null}
                </div>
                <p className="text-sm text-muted-foreground">ID: {tunnel.id}</p>
                {tunnel.metadata?.description ? (
                  <p className="text-sm text-muted-foreground">{tunnel.metadata.description}</p>
                ) : null}
              </div>

              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon">
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem disabled>编辑（请通过 API）</DropdownMenuItem>
                  <DropdownMenuItem disabled>回滚（即将支持）</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>

            <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
              <div className="flex items-center gap-2">
                <Network className="h-4 w-4" />
                {tunnel.nodeIds.length > 0 ? `${tunnel.nodeIds.join(", ")}` : "所有节点"}
              </div>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4" />
                {tunnel.updatedAt
                  ? formatDistanceToNowStrict(new Date(tunnel.updatedAt), { addSuffix: true })
                  : "未记录更新时间"}
              </div>
              <div>空闲断开 {Math.round((tunnel.idleTimeout ?? 0) / 1_000_000_000) || "默认"} 秒</div>
            </div>
          </div>
        </Card>
      ))}
    </div>
  )
}
