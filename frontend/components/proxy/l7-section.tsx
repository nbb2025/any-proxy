'use client'

import Link from "next/link"
import { useMemo, useState } from "react"
import { useRouter } from "next/navigation"
import { Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ResourcesTabs } from "@/components/resources/resources-tabs"
import { ResourcesTable } from "@/components/resources/resources-table"
import { useSnapshot } from "@/hooks/use-snapshot"
import { DomainDetailDialog } from "@/components/proxy/domain-detail-dialog"
import type { DomainRoute } from "@/lib/types"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"
import { deleteDomainRequest } from "@/lib/api"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"

export function ProxyL7Section() {
  const router = useRouter()
  const { snapshot, loading, error, reload } = useSnapshot()
  const [detailDomain, setDetailDomain] = useState<DomainRoute | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<DomainRoute | null>(null)
  const [deletePending, setDeletePending] = useState(false)

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
      <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-border text-sm text-muted-foreground">
        正在加载 L7 代理数据...
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-destructive/40 text-sm text-muted-foreground">
        <p>加载 L7 代理数据失败：{error}</p>
        <Button variant="outline" size="sm" onClick={reload}>
          重试
        </Button>
      </div>
    )
  }

  if (!snapshot) {
    return null
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      setDeletePending(true)
      const token = await ensureAccessToken()
      if (!token) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      await deleteDomainRequest(token, deleteTarget.id)
      setDeleteTarget(null)
      reload()
    } catch (err) {
      const status = (err as { status?: number }).status
      if (status === 401) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      setFormError(err instanceof Error ? err.message : "删除失败，请稍后重试")
    } finally {
      setDeletePending(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <ResourcesTabs summary={summary} />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm text-muted-foreground">
          <p>
            共 {summary.totalDomains} 个应用代理，汇聚 {summary.totalUpstreams} 条上游。
          </p>
          <p>{summary.tlsEnabled} 个域名已启用 HTTPS。</p>
        </div>
        <Button size="sm" asChild>
          <Link href="/resources/l7/new">
            <Plus className="mr-2 h-4 w-4" />
            新增应用代理
          </Link>
        </Button>
      </div>

      <ResourcesTable
        domains={snapshot.domains}
        pending={deletePending}
        onView={(domain) => setDetailDomain(domain)}
        onDelete={(domain) => setDeleteTarget(domain)}
      />

      <DomainDetailDialog
        open={Boolean(detailDomain)}
        domain={detailDomain}
        onOpenChange={(open) => {
          if (!open) {
            setDetailDomain(null)
          }
        }}
      />

      <AlertDialog
        open={Boolean(deleteTarget)}
        onOpenChange={(open) => {
          if (!open && !deletePending) {
            setDeleteTarget(null)
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除该应用代理？</AlertDialogTitle>
            <AlertDialogDescription>
              域名 {deleteTarget?.domain} 删除后会立即从 OpenResty 配置中移除，操作不可恢复。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletePending}>取消</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete} disabled={deletePending}>
              {deletePending ? "删除中..." : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
