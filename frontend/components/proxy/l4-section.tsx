'use client'

import { Shield } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"

export function ProxyL4Section() {
  return (
    <Card className="flex flex-col items-center justify-center gap-4 border-dashed border-border/70 bg-muted/20 py-16 text-center">
      <Shield className="h-10 w-10 text-muted-foreground" />
      <div className="space-y-2">
        <h3 className="text-lg font-semibold text-foreground">L4 传输层代理功能建设中</h3>
        <p className="text-sm text-muted-foreground">
          该功能将支持 TCP/UDP 代理、四层负载均衡、细粒度 ACL 等能力，当前仍在开发中。
        </p>
      </div>
      <Button variant="outline" size="sm" disabled>
        即将开放
      </Button>
    </Card>
  )
}
