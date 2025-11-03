import { Card } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"

export function GeneralSettings() {
  return (
    <Card className="border-border bg-card p-6">
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-semibold text-foreground">常规设置</h3>
          <p className="text-sm text-muted-foreground">管理系统的基本配置信息</p>
        </div>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="system-name">系统名称</Label>
            <Input id="system-name" defaultValue="CDN 管理系统" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="company-name">公司名称</Label>
            <Input id="company-name" defaultValue="示例科技有限公司" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="timezone">时区</Label>
            <Select defaultValue="asia-shanghai">
              <SelectTrigger id="timezone">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="asia-shanghai">亚洲/上海 (UTC+8)</SelectItem>
                <SelectItem value="asia-tokyo">亚洲/东京 (UTC+9)</SelectItem>
                <SelectItem value="america-new-york">美洲/纽约 (UTC-5)</SelectItem>
                <SelectItem value="europe-london">欧洲/伦敦 (UTC+0)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="language">语言</Label>
            <Select defaultValue="zh-cn">
              <SelectTrigger id="language">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="zh-cn">简体中文</SelectItem>
                <SelectItem value="zh-tw">繁体中文</SelectItem>
                <SelectItem value="en">English</SelectItem>
                <SelectItem value="ja">日本語</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">系统描述</Label>
            <Textarea id="description" defaultValue="CDN + 内网穿透管理平台" rows={3} />
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
