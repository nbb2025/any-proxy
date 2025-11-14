'use client'

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import type { EdgeNode, TunnelAgent, TunnelGroup } from "@/lib/types"
import {
  fetchTunnelGroups,
  fetchTunnelAgents,
  fetchNodeInventory,
  createTunnelGroupRequest,
  updateTunnelGroupRequest,
  deleteTunnelGroupRequest,
  createTunnelAgentRequest,
  updateTunnelAgentRequest,
  deleteTunnelAgentRequest,
  refreshTunnelAgentKeyRequest,
  type TunnelGroupPayload,
  type TunnelAgentPayload,
} from "@/lib/api"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"

export interface TunnelInventoryState {
  loading: boolean
  error: string | null
  groups: TunnelGroup[]
  agents: TunnelAgent[]
  nodes: EdgeNode[]
  reload: () => void
  createGroup: (payload: TunnelGroupPayload) => Promise<void>
  updateGroup: (id: string, payload: TunnelGroupPayload) => Promise<void>
  deleteGroup: (id: string) => Promise<void>
  createAgent: (payload: TunnelAgentPayload) => Promise<string | undefined>
  updateAgent: (id: string, payload: TunnelAgentPayload) => Promise<string | undefined>
  deleteAgent: (id: string) => Promise<void>
  refreshAgentKey: (id: string) => Promise<string>
}

export function useTunnelInventory(): TunnelInventoryState {
  const router = useRouter()
  const [groups, setGroups] = useState<TunnelGroup[]>([])
  const [agents, setAgents] = useState<TunnelAgent[]>([])
  const [nodes, setNodes] = useState<EdgeNode[]>([])
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
      const [fetchedGroups, fetchedAgents, nodeInventory] = await Promise.all([
        fetchTunnelGroups(token),
        fetchTunnelAgents(token),
        fetchNodeInventory(token),
      ])
      setGroups(fetchedGroups)
      setAgents(fetchedAgents)
      setNodes(nodeInventory.nodes)
    } catch (err) {
      console.error("[tunnels] load inventory failed", err)
      const status = (err as { status?: number })?.status
      if (status === 401) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      setError(err instanceof Error ? err.message : "加载隧道路由失败")
    } finally {
      setLoading(false)
    }
  }, [router])

  useEffect(() => {
    let cancelled = false
    const run = async () => {
      await load()
      if (cancelled) return
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [load, version])

  const reload = useCallback(() => {
    setVersion((value) => value + 1)
  }, [])

  const ensureToken = useCallback(async () => {
    const token = await ensureAccessToken()
    if (!token) {
      clearAuthTokens()
      router.replace("/login")
      throw new Error("登录已过期")
    }
    return token
  }, [router])

  const createGroup = useCallback(
    async (payload: TunnelGroupPayload) => {
      const token = await ensureToken()
      await createTunnelGroupRequest(token, payload)
      reload()
    },
    [ensureToken, reload],
  )

  const updateGroup = useCallback(
    async (id: string, payload: TunnelGroupPayload) => {
      const token = await ensureToken()
      await updateTunnelGroupRequest(token, id, payload)
      reload()
    },
    [ensureToken, reload],
  )

  const deleteGroup = useCallback(
    async (id: string) => {
      const token = await ensureToken()
      await deleteTunnelGroupRequest(token, id)
      reload()
    },
    [ensureToken, reload],
  )

  const createAgent = useCallback(
    async (payload: TunnelAgentPayload) => {
      const token = await ensureToken()
      const res = await createTunnelAgentRequest(token, payload)
      reload()
      return res.agentKey
    },
    [ensureToken, reload],
  )

  const updateAgent = useCallback(
    async (id: string, payload: TunnelAgentPayload) => {
      const token = await ensureToken()
      const res = await updateTunnelAgentRequest(token, id, payload)
      reload()
      return res.agentKey
    },
    [ensureToken, reload],
  )

  const deleteAgent = useCallback(
    async (id: string) => {
      const token = await ensureToken()
      await deleteTunnelAgentRequest(token, id)
      reload()
    },
    [ensureToken, reload],
  )

  const refreshAgentKey = useCallback(
    async (id: string) => {
      const token = await ensureToken()
      const key = await refreshTunnelAgentKeyRequest(token, id)
      reload()
      return key
    },
    [ensureToken, reload],
  )

  return {
    loading,
    error,
    groups,
    agents,
    nodes,
    reload,
    createGroup,
    updateGroup,
    deleteGroup,
    createAgent,
    updateAgent,
    deleteAgent,
    refreshAgentKey,
  }
}
