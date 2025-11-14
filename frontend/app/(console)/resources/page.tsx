'use client'

import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { ProxyL7Section } from "@/components/proxy/l7-section"
import { ProxyL4Section } from "@/components/proxy/l4-section"
import { ProxyTunnelSection } from "@/components/proxy/tunnel-section"

export default function ProxyManagementPage() {
  return (
    <div className="flex h-full flex-col">
      <header className="border-b border-border px-8 py-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Proxy Control</p>
          <h1 className="text-2xl font-semibold text-foreground">代理管理</h1>
          <p className="text-sm text-muted-foreground">
            统一管理 L7/L4 代理以及内网穿透入口，集中编排域名、上游与 Agent 拓扑。
          </p>
        </div>
      </header>

      <div className="flex-1 overflow-hidden px-8 pb-8 pt-6">
        <Tabs defaultValue="l7" className="flex h-full flex-col gap-4">
          <TabsList className="bg-muted/50 p-1">
            <TabsTrigger value="l7">L7 应用层代理</TabsTrigger>
            <TabsTrigger value="l4">L4 传输层代理</TabsTrigger>
            <TabsTrigger value="tunnel">内网穿透</TabsTrigger>
          </TabsList>

          <div className="flex-1 overflow-hidden">
            <TabsContent
              value="l7"
              className="h-full overflow-auto rounded-2xl border border-border/70 bg-card p-6 shadow-sm"
            >
              <div className="space-y-4">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">L7 应用层代理</h2>
                  <p className="text-sm text-muted-foreground">
                    管理 HTTP/HTTPS 域名、上游服务与调度策略，支持一键同步到 Edge。
                  </p>
                </div>
                <ProxyL7Section />
              </div>
            </TabsContent>

            <TabsContent
              value="l4"
              className="h-full overflow-auto rounded-2xl border border-border/70 bg-card p-6 shadow-sm"
            >
              <div className="space-y-4">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">L4 传输层代理</h2>
                  <p className="text-sm text-muted-foreground">
                    规划 TCP/UDP 入口、四层转发与健康探测能力，敬请期待。
                  </p>
                </div>
                <ProxyL4Section />
              </div>
            </TabsContent>

            <TabsContent
              value="tunnel"
              className="h-full overflow-auto rounded-2xl border border-border/70 bg-card p-6 shadow-sm"
            >
              <div className="space-y-4">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">内网穿透</h2>
                  <p className="text-sm text-muted-foreground">
                    快速分发 tunnel agent、管理节点心跳，并可视化会话与任务拓扑。
                  </p>
                </div>
                <ProxyTunnelSection />
              </div>
            </TabsContent>
          </div>
        </Tabs>
      </div>
    </div>
  )
}
