import { Card } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

export function SecuritySettings() {
  return (
    <Card className="border-border bg-card p-6">
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-semibold text-foreground">安全设置</h3>
          <p className="text-sm text-muted-foreground">配置系统安全相关选项</p>
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>双因素认证</Label>
              <p className="text-sm text-muted-foreground">启用双因素认证以提高账户安全性</p>
            </div>
            <Switch defaultChecked />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>IP 白名单</Label>
              <p className="text-sm text-muted-foreground">仅允许白名单中的 IP 访问管理后台</p>
            </div>
            <Switch />
          </div>

          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>登录日志</Label>
              <p className="text-sm text-muted-foreground">记录所有登录活动</p>
            </div>
            <Switch defaultChecked />
          </div>

          <div className="space-y-2">
            <Label htmlFor="session-timeout">会话超时时间</Label>
            <Select defaultValue="30">
              <SelectTrigger id="session-timeout">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="15">15 分钟</SelectItem>
                <SelectItem value="30">30 分钟</SelectItem>
                <SelectItem value="60">1 小时</SelectItem>
                <SelectItem value="120">2 小时</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="password-policy">密码策略</Label>
            <Select defaultValue="strong">
              <SelectTrigger id="password-policy">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="weak">弱 (最少 6 位)</SelectItem>
                <SelectItem value="medium">中 (最少 8 位，包含字母和数字)</SelectItem>
                <SelectItem value="strong">强 (最少 12 位，包含大小写字母、数字和特殊字符)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="current-password">当前密码</Label>
            <Input id="current-password" type="password" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="new-password">新密码</Label>
            <Input id="new-password" type="password" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirm-password">确认新密码</Label>
            <Input id="confirm-password" type="password" />
          </div>
        </div>

        <div className="flex justify-end gap-2">
          <Button variant="outline">取消</Button>
          <Button>更新密码</Button>
        </div>
      </div>
    </Card>
  )
}
