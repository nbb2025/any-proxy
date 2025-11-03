import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Search, Plus, Filter, Download } from "lucide-react"
import { EdgeClustersGrid } from "@/components/edge/clusters-grid"

export default function EdgeClustersPage() {
  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-semibold text-foreground">边缘集群</h1>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <Download className="mr-2 h-4 w-4" />
            导出
          </Button>
          <Button variant="default" size="sm">
            <Plus className="mr-2 h-4 w-4" />
            创建集群
          </Button>
        </div>
      </header>

      <div className="flex-1 space-y-6 overflow-auto p-8">
        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="搜索集群名称或区域..." className="pl-10" />
          </div>
          <Button variant="outline" size="sm">
            <Filter className="mr-2 h-4 w-4" />
            筛选
          </Button>
        </div>

        <EdgeClustersGrid />
      </div>
    </div>
  )
}
