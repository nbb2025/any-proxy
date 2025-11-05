'use client'

import { useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Search } from "lucide-react"
import { Input } from "@/components/ui/input"
import { ResourcesTabs } from "@/components/resources/resources-tabs"
import { ResourcesTable } from "@/components/resources/resources-table"
import { useSnapshot } from "@/hooks/use-snapshot"

export default function ResourcesPage() {
  const { snapshot, loading, error, reload } = useSnapshot()

  const summary = useMemo(() => {
    if (!snapshot) {
      return { totalDomains: 0, totalUpstreams: 0, tlsEnabled: 0 }
    }
    const totalDomains = snapshot.domains.length
    const totalUpstreams = snapshot.domains.reduce((sum, domain) => sum + domain.upstreams.length, 0)
    const tlsEnabled = snapshot.domains.filter((domain) => domain.enableTls).length
    return { totalDomains, totalUpstreams, tlsEnabled }
  }, [snapshot])

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
        正在加载域名与上游数据...
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-sm text-muted-foreground">
        <p>加载数据失败：{error}</p>
        <Button variant="outline" onClick={reload}>
          重试
        </Button>
      </div>
    )
  }

  if (!snapshot) {
    return null
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">域名与上游</h1>
          <p className="text-sm text-muted-foreground">查看每个域名关联的上游服务与调度策略。</p>
        </div>
      </header>

      <div className="flex-1 space-y-6 overflow-auto p-8">
        <ResourcesTabs summary={summary} />

        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="支持通过 API 查询，界面筛选即将开放" className="pl-10" readOnly />
          </div>
          <Button variant="outline" size="sm" disabled>
            搜索
          </Button>
        </div>

        <ResourcesTable domains={snapshot.domains} />
      </div>
    </div>
  )
}
