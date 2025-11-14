'use client'

import { ProxyTunnelSection } from "@/components/proxy/tunnel-section"

export default function TunnelsPage() {
  return (
    <div className="flex h-full flex-col">
      <header className="border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">内网穿透</h1>
          <p className="text-sm text-muted-foreground">配置 tunnel 入口、分发 agent，并监控在线会话/心跳。</p>
        </div>
      </header>

      <div className="flex-1 space-y-6 overflow-auto p-8">
        <ProxyTunnelSection />
      </div>
    </div>
  )
}
