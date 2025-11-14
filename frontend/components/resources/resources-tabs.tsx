"use client"

import { Card } from "@/components/ui/card"

interface ResourcesTabsProps {
  summary: {
    totalDomains: number
    totalUpstreams: number
    tlsEnabled: number
  }
}

const formatNumber = (value: number) => {
  if (value > 1000) {
    return `${(value / 1000).toFixed(1)}k`
  }
  return String(value)
}

export function ResourcesTabs({ summary }: ResourcesTabsProps) {
  const stats = [
    {
      label: "名称（应用代理）",
      value: summary.totalDomains,
      hint: "所有 L7 代理的数量",
    },
    {
      label: "转发配置",
      value: summary.totalUpstreams,
      hint: "当前生效的上游条目",
    },
    {
      label: "证书状态",
      value: summary.tlsEnabled,
      hint: "启用 HTTPS 的代理数量",
    },
  ]

  return (
    <div className="grid gap-3 md:grid-cols-3">
      {stats.map((stat) => (
        <Card key={stat.label} className="border-border bg-card p-4">
          <p className="text-xs uppercase text-muted-foreground/70">{stat.label}</p>
          <p className="text-2xl font-semibold text-foreground">{formatNumber(stat.value)}</p>
          <p className="text-xs text-muted-foreground">{stat.hint}</p>
        </Card>
      ))}
    </div>
  )
}
