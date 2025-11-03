import { Card } from "@/components/ui/card"

const stats = [
  { label: "边缘", value: 4 },
  { label: "EIPs", value: 4 },
  { label: "标签", value: 0 },
  { label: "资源", value: 1 },
  { label: "别名对象", value: 0 },
  { label: "负载均衡对象", value: 0 },
  { label: "插件", value: 13 },
  { label: "对象", value: 2 },
]

export function DashboardStats() {
  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card className="border-border bg-card p-6">
        <div className="grid grid-cols-3 gap-4">
          {stats.slice(0, 3).map((stat) => (
            <div key={stat.label} className="space-y-1">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="text-2xl font-semibold text-foreground">{stat.value}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card className="border-border bg-card p-6">
        <div className="grid grid-cols-3 gap-4">
          {stats.slice(3, 6).map((stat) => (
            <div key={stat.label} className="space-y-1">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="text-2xl font-semibold text-foreground">{stat.value}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card className="border-border bg-card p-6">
        <div className="grid grid-cols-2 gap-4">
          {stats.slice(6, 8).map((stat) => (
            <div key={stat.label} className="space-y-1">
              <p className="text-sm text-muted-foreground">{stat.label}</p>
              <p className="text-2xl font-semibold text-foreground">{stat.value}</p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
