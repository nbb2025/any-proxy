import { Card } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"

interface OverviewCard {
  title: string
  value: string
  trend?: string
  delta?: string
}

const defaultOverview: OverviewCard[] = [
  { title: "请求", value: "--", trend: "待接入监控" },
  { title: "流量", value: "--", trend: "待接入监控" },
  { title: "错误率", value: "--", trend: "待接入监控" },
  { title: "事件", value: "--", trend: "待接入监控" },
]

export function DashboardOverview() {
  return (
    <Card className="grid gap-4 border border-white/10 bg-gradient-to-br from-[#0B1020] to-[#05070d] p-6 shadow-[0_12px_60px_rgba(0,0,0,0.45)] md:grid-cols-4">
      {defaultOverview.map((item) => (
        <div key={item.title} className="flex flex-col gap-3 rounded-xl border border-white/5 bg-white/5 p-4">
          <p className="text-xs uppercase tracking-widest text-slate-400">{item.title}</p>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-semibold text-white">{item.value}</span>
            {item.delta ? <span className="text-xs text-emerald-300">{item.delta}</span> : null}
          </div>
          <p className="text-[11px] text-slate-400">{item.trend}</p>
          <Progress value={12} className="h-1 bg-white/10" />
        </div>
      ))}
    </Card>
  )
}

