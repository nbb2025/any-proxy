"use client"

import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"

interface PolicyTabsProps {
  summary: {
    total: number
    tcp: number
    udp: number
    quic: number
  }
}

export function PolicyTabs({ summary }: PolicyTabsProps) {
  return (
    <Tabs defaultValue="all" className="w-full">
      <TabsList className="flex-wrap justify-start">
        <TabsTrigger value="all">全部隧道 ({summary.total})</TabsTrigger>
        <TabsTrigger value="tcp">TCP ({summary.tcp})</TabsTrigger>
        <TabsTrigger value="udp">UDP ({summary.udp})</TabsTrigger>
        <TabsTrigger value="quic">QUIC ({summary.quic})</TabsTrigger>
      </TabsList>
    </Tabs>
  )
}
