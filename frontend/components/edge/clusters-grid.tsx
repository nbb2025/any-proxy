import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { MoreHorizontal, Server, Activity, TrendingUp, AlertCircle } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

const clusters = [
  {
    id: "cluster-001",
    name: "华北集群",
    region: "华北",
    status: "healthy",
    nodes: 12,
    activeNodes: 12,
    totalRequests: "45.2K",
    avgLatency: "12ms",
    uptime: "99.99%",
    bandwidth: "4.5 Gbps",
    trend: "+12.5%",
  },
  {
    id: "cluster-002",
    name: "华东集群",
    region: "华东",
    status: "healthy",
    nodes: 18,
    activeNodes: 17,
    totalRequests: "67.8K",
    avgLatency: "15ms",
    uptime: "99.95%",
    bandwidth: "6.2 Gbps",
    trend: "+8.3%",
  },
  {
    id: "cluster-003",
    name: "华南集群",
    region: "华南",
    status: "warning",
    nodes: 10,
    activeNodes: 8,
    totalRequests: "32.1K",
    avgLatency: "18ms",
    uptime: "98.50%",
    bandwidth: "3.1 Gbps",
    trend: "-5.2%",
  },
  {
    id: "cluster-004",
    name: "西南集群",
    region: "西南",
    status: "healthy",
    nodes: 8,
    activeNodes: 8,
    totalRequests: "21.5K",
    avgLatency: "14ms",
    uptime: "99.92%",
    bandwidth: "2.8 Gbps",
    trend: "+15.7%",
  },
]

export function EdgeClustersGrid() {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      {clusters.map((cluster) => (
        <Card key={cluster.id} className="border-border bg-card p-6">
          <div className="space-y-4">
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <h3 className="text-lg font-semibold text-foreground">{cluster.name}</h3>
                <p className="text-sm text-muted-foreground">
                  {cluster.region} · {cluster.id}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={cluster.status === "healthy" ? "default" : "destructive"}>
                  {cluster.status === "healthy" ? (
                    <Activity className="mr-1 h-3 w-3" />
                  ) : (
                    <AlertCircle className="mr-1 h-3 w-3" />
                  )}
                  {cluster.status === "healthy" ? "健康" : "警告"}
                </Badge>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon">
                      <MoreHorizontal className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem>查看详情</DropdownMenuItem>
                    <DropdownMenuItem>编辑配置</DropdownMenuItem>
                    <DropdownMenuItem>扩容节点</DropdownMenuItem>
                    <DropdownMenuItem className="text-destructive">删除集群</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Server className="h-4 w-4" />
                  节点数量
                </div>
                <p className="text-2xl font-semibold text-foreground">
                  {cluster.activeNodes}/{cluster.nodes}
                </p>
              </div>

              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">总请求</p>
                <div className="flex items-baseline gap-2">
                  <p className="text-2xl font-semibold text-foreground">{cluster.totalRequests}</p>
                  <span
                    className={`flex items-center text-xs ${cluster.trend.startsWith("+") ? "text-primary" : "text-destructive"}`}
                  >
                    <TrendingUp className="mr-1 h-3 w-3" />
                    {cluster.trend}
                  </span>
                </div>
              </div>

              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">平均延迟</p>
                <p className="text-2xl font-semibold text-foreground">{cluster.avgLatency}</p>
              </div>

              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">带宽使用</p>
                <p className="text-2xl font-semibold text-foreground">{cluster.bandwidth}</p>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-border pt-4">
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 rounded-full bg-primary" />
                <span className="text-sm text-muted-foreground">可用性</span>
              </div>
              <span className="text-sm font-medium text-foreground">{cluster.uptime}</span>
            </div>
          </div>
        </Card>
      ))}
    </div>
  )
}
