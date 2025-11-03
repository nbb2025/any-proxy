"use client"

import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface ResourcesTabsProps {
  summary: {
    totalDomains: number
    totalUpstreams: number
    tlsEnabled: number
  }
}

export function ResourcesTabs({ summary }: ResourcesTabsProps) {
  return (
    <Tabs defaultValue="overview" className="w-full">
      <TabsList className="flex-wrap justify-start">
        <TabsTrigger value="overview">域名 ({summary.totalDomains})</TabsTrigger>
        <TabsTrigger value="upstreams">上游节点 ({summary.totalUpstreams})</TabsTrigger>
        <TabsTrigger value="tls">启用 HTTPS ({summary.tlsEnabled})</TabsTrigger>
      </TabsList>
    </Tabs>
  )
}
