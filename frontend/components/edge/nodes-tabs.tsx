"use client"

import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface EdgeNodesTabsProps {
  summary: {
    total: number
    withDomains: number
    withTunnels: number
    both: number
  }
}

export function EdgeNodesTabs({ summary }: EdgeNodesTabsProps) {
  return (
    <Tabs defaultValue="overview" className="w-full">
      <TabsList className="flex-wrap justify-start">
        <TabsTrigger value="overview">全部节点 ({summary.total})</TabsTrigger>
        <TabsTrigger value="domains">仅域名 ({summary.withDomains})</TabsTrigger>
        <TabsTrigger value="tunnels">仅隧道 ({summary.withTunnels})</TabsTrigger>
        <TabsTrigger value="both">双活 ({summary.both})</TabsTrigger>
      </TabsList>
    </Tabs>
  )
}
