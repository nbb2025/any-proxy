import { Card } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"

export function NotificationSettings() {
  return (
    <Card className="border-border bg-card p-6">
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-semibold text-foreground">通知设置</h3>
          <p className="text-sm text-muted-foreground">管理系统通知和告警配置</p>
        </div>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">通知邮箱</Label>
            <Input id="email" type="email" defaultValue="admin@example.com" />
          </div>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <p className="text-sm font-medium text-foreground">邮件通知</p>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>系统告警</Label>
                <p className="text-sm text-muted-foreground">节点离线、资源异常等</p>
              </div>
              <Switch defaultChecked />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>性能报告</Label>
                <p className="text-sm text-muted-foreground">每日性能统计报告</p>
              </div>
              <Switch defaultChecked />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>安全事件</Label>
                <p className="text-sm text-muted-foreground">DDoS 攻击、异常访问等</p>
              </div>
              <Switch defaultChecked />
            </div>
          </div>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <p className="text-sm font-medium text-foreground">Webhook 通知</p>

            <div className="space-y-2">
              <Label htmlFor="webhook-url">Webhook URL</Label>
              <Input id="webhook-url" placeholder="https://example.com/webhook" />
            </div>

            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>启用 Webhook</Label>
                <p className="text-sm text-muted-foreground">发送通知到指定的 Webhook 地址</p>
              </div>
              <Switch />
            </div>
          </div>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <p className="text-sm font-medium text-foreground">告警阈值</p>

            <div className="space-y-2">
              <Label htmlFor="cpu-threshold">CPU 使用率阈值 (%)</Label>
              <Input id="cpu-threshold" type="number" defaultValue="80" />
            </div>

            <div className="space-y-2">
              <Label htmlFor="memory-threshold">内存使用率阈值 (%)</Label>
              <Input id="memory-threshold" type="number" defaultValue="85" />
            </div>

            <div className="space-y-2">
              <Label htmlFor="error-threshold">错误率阈值 (%)</Label>
              <Input id="error-threshold" type="number" defaultValue="5" />
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <Button variant="outline">重置</Button>
          <Button>保存更改</Button>
        </div>
      </div>
    </Card>
  )
}
