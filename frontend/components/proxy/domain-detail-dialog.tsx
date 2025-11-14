'use client'

import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import type { DomainRoute } from "@/lib/types"

const formatDuration = (value?: number): string => {
  if (!value) return "—"
  const seconds = Math.round(value / 1_000_000_000)
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h`
}

export interface DomainDetailDialogProps {
  open: boolean
  domain: DomainRoute | null
  onOpenChange: (open: boolean) => void
}

export function DomainDetailDialog({ open, domain, onOpenChange }: DomainDetailDialogProps) {
  if (!domain) {
    return null
  }

  const inbound = domain.metadata?.inboundListeners ?? []
  const outbound = domain.metadata?.outboundListeners ?? []

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{domain.metadata?.displayName || domain.domain}</DialogTitle>
          <p className="text-sm text-muted-foreground">应用代理详情</p>
        </DialogHeader>
        <ScrollArea className="max-h-[60vh] pr-4">
          <div className="space-y-4 text-sm text-muted-foreground">
            <section className="space-y-2">
              <p className="text-xs uppercase text-muted-foreground/70">请求配置</p>
              <p className="font-mono text-base text-foreground">{domain.domain}</p>
              <div className="flex flex-wrap gap-2 text-xs">
                {inbound.length > 0
                  ? inbound.map((listener, index) => (
                      <Badge key={`${domain.id}-in-${index}`} variant="outline">
                        {listener.protocol || "HTTP"}:{listener.port || (listener.protocol === "HTTPS" ? 443 : 80)}
                      </Badge>
                    ))
                  : [
                      <Badge key="default-http" variant="outline">
                        HTTP:80
                      </Badge>,
                      domain.enableTls ? (
                        <Badge key="default-https" variant="outline">
                          HTTPS:443
                        </Badge>
                      ) : null,
                    ]}
              </div>
            </section>
            <section className="space-y-2">
              <p className="text-xs uppercase text-muted-foreground/70">转发配置</p>
              <div className="space-y-3">
                {domain.upstreams.map((upstream, index) => (
                  <div key={`${domain.id}-up-${index}`} className="rounded-md border border-border/60 p-3">
                    <p className="font-mono text-sm text-foreground">{upstream.address}</p>
                    <p className="text-xs">
                      权重 {upstream.weight ?? 1}
                      {upstream.maxFails ? ` · 最大失败 ${upstream.maxFails}` : ""}
                      {upstream.failTimeout ? ` · 熔断 ${formatDuration(Number(upstream.failTimeout))}` : ""}
                      {upstream.usePersistent ? " · 长连接" : ""}
                      {upstream.healthCheck ? ` · 健康检查 ${upstream.healthCheck}` : ""}
                    </p>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap gap-2 text-xs">
                {outbound.length > 0
                  ? outbound.map((listener, index) => (
                      <Badge key={`${domain.id}-out-${index}`} variant="outline">
                        {listener.protocol || "HTTP"}:{listener.port || (listener.protocol === "HTTPS" ? 443 : 80)}
                      </Badge>
                    ))
                  : null}
              </div>
            </section>
            <section className="space-y-2">
              <p className="text-xs uppercase text-muted-foreground/70">代理行为</p>
              <p>Cookie 粘连：{domain.metadata?.sticky ? "开启" : "关闭"}</p>
              <p>代理超时：{formatDuration(domain.metadata?.timeoutProxy)}</p>
              <p>读取超时：{formatDuration(domain.metadata?.timeoutRead)}</p>
              <p>发送超时：{formatDuration(domain.metadata?.timeoutSend)}</p>
            </section>
            {domain.edgeNodes.length > 0 ? (
              <section className="space-y-2">
                <p className="text-xs uppercase text-muted-foreground/70">目标节点</p>
                <div className="flex flex-wrap gap-2 text-xs">
                  {domain.edgeNodes.map((node) => (
                    <Badge key={node} variant="outline">
                      {node}
                    </Badge>
                  ))}
                </div>
              </section>
            ) : null}
            {domain.metadata?.remark ? (
              <section className="space-y-2">
                <p className="text-xs uppercase text-muted-foreground/70">备注</p>
                <p className="text-sm text-foreground">{domain.metadata.remark}</p>
              </section>
            ) : null}
          </div>
        </ScrollArea>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
