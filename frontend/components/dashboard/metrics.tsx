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
    <Card className="border border-white/10 bg-gradient-to-br from-[#111827] to-[#0B1020] p-6 shadow-[0_20px_80px_rgba(0,0,0,0.45)]">
      <div className="flex flex-wrap items-center justify-between gap-6 border-b border-white/5 pb-6">
        <div className="space-y-1">
          <p className="text-sm uppercase tracking-[0.2em] text-emerald-300/80">版本快照</p>
          <div className="flex items-center gap-4">
            <span className="text-4xl font-semibold text-white">v{version}</span>
            <Badge className="flex items-center gap-1 bg-emerald-500/15 text-emerald-200">
              <CalendarClock className="h-3 w-3" />
              {formattedGeneratedAt}
            </Badge>
          </div>
        </div>
        <div className="max-w-sm rounded-lg border border-white/5 bg-white/5 px-4 py-3 text-xs text-slate-300">
          控制平面在配置变更后会推送新版本，边缘与隧道 Agent 自动轮询最新快照并收敛配置。
        </div>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {metrics.map((metric) => (
          <div
            key={metric.label}
            className="rounded-xl border border-white/5 bg-white/5 p-4 shadow-inner shadow-black/30"
          >
            <p className="text-xs uppercase tracking-widest text-slate-400">{metric.label}</p>
            <div className="mt-2 text-3xl font-semibold text-white">{metric.value}</div>
            {metric.description ? (
              <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{metric.description}</p>
            ) : null}
          </div>
        ))}
      </div>
    </Card>
  )
}
