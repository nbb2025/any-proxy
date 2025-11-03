"use client"

import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"

export function SettingsTabs() {
  return (
    <Tabs defaultValue="general" className="w-full">
      <TabsList className="grid w-full grid-cols-4">
        <TabsTrigger value="general">常规</TabsTrigger>
        <TabsTrigger value="security">安全</TabsTrigger>
        <TabsTrigger value="notifications">通知</TabsTrigger>
        <TabsTrigger value="api">API</TabsTrigger>
      </TabsList>
    </Tabs>
  )
}
