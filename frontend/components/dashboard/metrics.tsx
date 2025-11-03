import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { CalendarClock } from "lucide-react"
import { format } from "date-fns"

export interface DashboardMetric {
  label: string
  value: string
  description?: string
}

interface DashboardMetricsProps {
  metrics: DashboardMetric[]
  version: number
  generatedAt: string
}

export function DashboardMetrics({ metrics, version, generatedAt }: DashboardMetricsProps) {
  const formattedGeneratedAt = format(new Date(generatedAt), "yyyy-MM-dd HH:mm:ss")

  return (
    <Card className="border-border bg-card p-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <p className="text-sm text-muted-foreground">当前配置版本</p>
          <div className="mt-1 flex items-center gap-3">
            <span className="text-3xl font-semibold text-foreground">v{version}</span>
            <Badge variant="secondary" className="flex items-center gap-1">
              <CalendarClock className="h-3 w-3" />
              {formattedGeneratedAt}
            </Badge>
          </div>
        </div>
        <p className="max-w-xs text-xs text-muted-foreground">
          控制平面在配置变更后会推送新版本，边缘与隧道 Agent 将自动拉取最新快照完成收敛。
        </p>
      </div>

      <div className="mt-6 grid gap-6 md:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => (
          <div key={metric.label} className="space-y-1">
            <p className="text-sm text-muted-foreground">{metric.label}</p>
            <div className="text-3xl font-semibold text-foreground">{metric.value}</div>
            {metric.description ? (
              <p className="text-xs text-muted-foreground">{metric.description}</p>
            ) : null}
          </div>
        ))}
      </div>
    </Card>
  )
}
