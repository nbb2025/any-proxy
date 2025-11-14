'use client'

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import type { EdgeNode, NodeCategory, NodeGroup } from "@/lib/types"
import {
  fetchNodeInventory,
  createNodeGroupRequest,
  updateNodeGroupRequest,
  deleteNodeGroupRequest,
  moveNodeToGroupRequest,
  updateNodeRequest,
  deleteNodeRequest,
  fetchAgentVersions,
  updateNodesDesiredVersionRequest,
} from "@/lib/api"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"

export interface NodeInventoryState {
  loading: boolean
  error: string | null
  groups: NodeGroup[]
  nodes: EdgeNode[]
  agentVersions: string[]
  latestResolvedVersion?: string
  reload: () => void
  createGroup: (category: NodeCategory, name: string, description?: string) => Promise<void>
  updateGroup: (id: string, name: string, description?: string) => Promise<void>
  deleteGroup: (id: string) => Promise<void>
  moveNode: (nodeId: string, groupId: string | null) => Promise<void>
  changeNodeCategory: (nodeId: string, category: NodeCategory) => Promise<void>
  deleteNode: (nodeId: string) => Promise<void>
  setDesiredVersion: (nodeId: string, version: string | null) => Promise<void>
  setDesiredVersionBulk: (nodeIds: string[], version: string | null) => Promise<void>
}

export function useNodeInventory(): NodeInventoryState {
  const router = useRouter()
  const [groups, setGroups] = useState<NodeGroup[]>([])
  const [nodes, setNodes] = useState<EdgeNode[]>([])
  const [agentVersions, setAgentVersions] = useState<string[]>(["latest"])
  const [latestResolvedVersion, setLatestResolvedVersion] = useState<string>("")
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
      const data = await fetchNodeInventory(token)
      setGroups(data.groups)
      setNodes(data.nodes)
      try {
        const listing = await fetchAgentVersions(token)
        setAgentVersions(listing.versions.length > 0 ? listing.versions : ["latest"])
        setLatestResolvedVersion(listing.latestResolved || "")
      } catch (err) {
        console.error("[nodes] failed to load agent versions", err)
        setAgentVersions(["latest"])
        setLatestResolvedVersion("")
      }
    } catch (err) {
      console.error("[nodes] failed to load inventory", err)
      const status = (err as { status?: number }).status
      if (status === 401) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      setError(err instanceof Error ? err.message : "加载节点数据失败")
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
    async (category: NodeCategory, name: string, description?: string) => {
      const token = await ensureToken()
      await createNodeGroupRequest(token, { category, name, description })
      reload()
    },
    [ensureToken, reload],
  )

  const updateGroup = useCallback(
    async (id: string, name: string, description?: string) => {
      const token = await ensureToken()
      await updateNodeGroupRequest(token, id, { name, description })
      reload()
    },
    [ensureToken, reload],
  )

  const deleteGroup = useCallback(
    async (id: string) => {
      const token = await ensureToken()
      await deleteNodeGroupRequest(token, id)
      reload()
    },
    [ensureToken, reload],
  )

  const moveNode = useCallback(
    async (nodeId: string, groupId: string | null) => {
      const token = await ensureToken()
      await moveNodeToGroupRequest(token, nodeId, groupId)
      reload()
    },
    [ensureToken, reload],
  )

  const changeNodeCategory = useCallback(
    async (nodeId: string, category: NodeCategory) => {
      const token = await ensureToken()
      await updateNodeRequest(token, nodeId, { category })
      reload()
    },
    [ensureToken, reload],
  )

  const deleteNode = useCallback(
    async (nodeId: string) => {
      const token = await ensureToken()
      await deleteNodeRequest(token, nodeId)
      reload()
    },
    [ensureToken, reload],
  )

  const setDesiredVersion = useCallback(
    async (nodeId: string, version: string | null) => {
      const token = await ensureToken()
      await updateNodeRequest(token, nodeId, { agentDesiredVersion: version })
      reload()
    },
    [ensureToken, reload],
  )

  const setDesiredVersionBulk = useCallback(
    async (nodeIds: string[], version: string | null) => {
      if (!nodeIds || nodeIds.length === 0) {
        throw new Error("请选择至少一个节点")
      }
      const token = await ensureToken()
      await updateNodesDesiredVersionRequest(token, { nodeIds, agentDesiredVersion: version })
      reload()
    },
    [ensureToken, reload],
  )

  return {
    loading,
    error,
    groups,
    nodes,
    agentVersions,
    latestResolvedVersion,
    reload,
    createGroup,
    updateGroup,
    deleteGroup,
    moveNode,
    changeNodeCategory,
    deleteNode,
    setDesiredVersion,
    setDesiredVersionBulk,
    latestResolvedVersion,
  }
}
