import { Card } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Copy, Eye, EyeOff, RefreshCw } from "lucide-react"

export function ApiSettings() {
  return (
    <Card className="border-border bg-card p-6">
      <div className="space-y-6">
        <div>
          <h3 className="text-lg font-semibold text-foreground">API 设置</h3>
          <p className="text-sm text-muted-foreground">管理 API 密钥和访问权限</p>
        </div>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="api-endpoint">API 端点</Label>
            <div className="flex gap-2">
              <Input id="api-endpoint" defaultValue="https://api.example.com/v1" readOnly />
              <Button variant="outline" size="icon">
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-foreground">主 API 密钥</p>
                <p className="text-xs text-muted-foreground">创建于 2024-01-01</p>
              </div>
              <Badge>活跃</Badge>
            </div>

            <div className="space-y-2">
              <Label htmlFor="api-key">密钥</Label>
              <div className="flex gap-2">
                <Input id="api-key" type="password" defaultValue="sk_live_1234567890abcdef" readOnly />
                <Button variant="outline" size="icon">
                  <Eye className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="icon">
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex gap-2">
              <Button variant="outline" size="sm">
                <RefreshCw className="mr-2 h-4 w-4" />
                重新生成
              </Button>
              <Button variant="outline" size="sm" className="text-destructive bg-transparent">
                撤销密钥
              </Button>
            </div>
          </div>

          <div className="space-y-4 rounded-lg border border-border p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-foreground">测试 API 密钥</p>
                <p className="text-xs text-muted-foreground">创建于 2024-01-10</p>
              </div>
              <Badge variant="secondary">测试</Badge>
            </div>

            <div className="space-y-2">
              <Label htmlFor="test-api-key">密钥</Label>
              <div className="flex gap-2">
                <Input id="test-api-key" type="password" defaultValue="sk_test_abcdef1234567890" readOnly />
                <Button variant="outline" size="icon">
                  <EyeOff className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="icon">
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex gap-2">
              <Button variant="outline" size="sm">
                <RefreshCw className="mr-2 h-4 w-4" />
                重新生成
              </Button>
              <Button variant="outline" size="sm" className="text-destructive bg-transparent">
                撤销密钥
              </Button>
            </div>
          </div>

          <Button variant="outline" className="w-full bg-transparent">
            创建新的 API 密钥
          </Button>

          <div className="space-y-2">
            <Label>API 使用统计</Label>
            <div className="grid grid-cols-3 gap-4 rounded-lg border border-border p-4">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">今日请求</p>
                <p className="text-2xl font-semibold text-foreground">12.5K</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">本月请求</p>
                <p className="text-2xl font-semibold text-foreground">345K</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">配额剩余</p>
                <p className="text-2xl font-semibold text-foreground">655K</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}
