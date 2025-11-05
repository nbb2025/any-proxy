'use client'

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import type { ConfigSnapshot } from "@/lib/types"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"
import { fetchSnapshot } from "@/lib/api"

type SnapshotState = {
  snapshot: ConfigSnapshot | null
  loading: boolean
  error: string | null
  reload: () => void
}

export function useSnapshot(): SnapshotState {
  const router = useRouter()
  const [snapshot, setSnapshot] = useState<ConfigSnapshot | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [version, setVersion] = useState(0)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const token = await ensureAccessToken()
      if (!token) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      const data = await fetchSnapshot(token)
      setSnapshot(data)
    } catch (err) {
      console.error("[snapshot] failed to load", err)
      const status = (err as { status?: number }).status
      if (status === 401) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      setError(err instanceof Error ? err.message : "获取配置失败")
    } finally {
      setLoading(false)
    }
  }, [router])

  useEffect(() => {
    let cancelled = false
    const wrapped = async () => {
      await load()
      if (cancelled) {
        return
      }
    }
    void wrapped()
    return () => {
      cancelled = true
    }
  }, [load, version])

  const reload = useCallback(() => {
    setVersion((value) => value + 1)
  }, [])

  return { snapshot, loading, error, reload }
}
