import { Card } from "@/components/ui/card"

export function DashboardResources() {
  return (
    <Card className="border-border bg-card p-6">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-muted-foreground">资源</h3>
          <div className="flex gap-4 text-xs text-muted-foreground">
            <span>1小时的请求趋势</span>
            <span>错误率</span>
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between rounded-lg border border-border bg-secondary/50 p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20">
                <span className="text-xs text-primary">⊕</span>
              </div>
              <span className="text-sm text-foreground">download-test-mq</span>
            </div>

            <div className="flex items-center gap-6">
              <div className="h-8 w-24">
                <svg className="h-full w-full" viewBox="0 0 100 30" preserveAspectRatio="none">
                  <path
                    d="M 0 20 L 20 18 L 40 22 L 60 15 L 80 19 L 100 17"
                    fill="none"
                    stroke="oklch(0.75 0.18 150)"
                    strokeWidth="2"
                  />
                </svg>
              </div>
              <span className="w-12 text-right text-sm text-foreground">671</span>
              <span className="w-12 text-right text-sm text-foreground">0%</span>
            </div>
          </div>
        </div>

        <div className="pt-4">
          <h3 className="text-sm font-medium text-foreground">边缘</h3>
          <div className="mt-4 grid grid-cols-3 gap-4">
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">区域</p>
              <div className="h-20 rounded-lg bg-secondary/50" />
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">边缘提供商</p>
              <div className="h-20 rounded-lg bg-secondary/50" />
            </div>
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground">边缘状态</p>
              <div className="h-20 rounded-lg bg-secondary/50" />
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}
