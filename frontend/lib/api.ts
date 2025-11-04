import { randomUUID } from "crypto"
import type { ConfigSnapshot, DomainRoute, TunnelRoute, Upstream } from "./types"

const CONTROL_PLANE_URL = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? process.env.CONTROL_PLANE_URL ?? ""

function toNumber(value: unknown | undefined): number | undefined {
  if (value === null || value === undefined) return undefined
  const num = Number(value)
  return Number.isFinite(num) ? num : undefined
}

function normaliseUpstream(raw: any): Upstream {
  return {
    address: String(raw?.address ?? ""),
    weight: toNumber(raw?.weight),
    maxFails: toNumber(raw?.maxFails),
    failTimeout: toNumber(raw?.failTimeout),
    healthCheck: raw?.healthCheck ? String(raw.healthCheck) : undefined,
    usePersistent: Boolean(raw?.usePersistent),
  }
}

function normaliseDomain(raw: any): DomainRoute {
  const upstreams = Array.isArray(raw?.upstreams) ? raw.upstreams.map(normaliseUpstream) : []
  return {
    id: String(raw?.id ?? randomUUID()),
    domain: String(raw?.domain ?? ""),
    enableTls: Boolean(raw?.enableTls),
    upstreams,
    edgeNodes: Array.isArray(raw?.edgeNodes) ? raw.edgeNodes.map((n: any) => String(n)) : [],
    metadata: raw?.metadata
      ? {
          sticky: Boolean(raw.metadata.sticky),
          timeoutProxy: toNumber(raw.metadata.timeoutProxy),
          timeoutRead: toNumber(raw.metadata.timeoutRead),
          timeoutSend: toNumber(raw.metadata.timeoutSend),
        }
      : undefined,
    updatedAt: raw?.updatedAt ? String(raw.updatedAt) : undefined,
  }
}

function normaliseTunnel(raw: any): TunnelRoute {
  return {
    id: String(raw?.id ?? randomUUID()),
    protocol: String(raw?.protocol ?? "tcp"),
    bindHost: String(raw?.bindHost ?? ""),
    bindPort: Number(raw?.bindPort ?? 0),
    target: String(raw?.target ?? ""),
    nodeIds: Array.isArray(raw?.nodeIds) ? raw.nodeIds.map((n: any) => String(n)) : [],
    idleTimeout: toNumber(raw?.idleTimeout),
    metadata: raw?.metadata
      ? {
          enableProxyProtocol: Boolean(raw.metadata.enableProxyProtocol),
          description: raw.metadata.description ? String(raw.metadata.description) : undefined,
        }
      : undefined,
    updatedAt: raw?.updatedAt ? String(raw.updatedAt) : undefined,
  }
}

function normaliseSnapshot(raw: any): ConfigSnapshot {
  const domains = Array.isArray(raw?.domains) ? raw.domains.map(normaliseDomain) : []
  const tunnels = Array.isArray(raw?.tunnels) ? raw.tunnels.map(normaliseTunnel) : []
  return {
    version: Number(raw?.version ?? 0),
    generatedAt: raw?.generatedAt ? String(raw.generatedAt) : new Date().toISOString(),
    domains,
    tunnels,
  }
}

export async function fetchSnapshot(token: string): Promise<ConfigSnapshot> {
  if (!CONTROL_PLANE_URL) {
    throw new Error("control plane URL is not configured")
  }
  if (!token) {
    throw new Error("access token missing")
  }
  const baseUrl = CONTROL_PLANE_URL.replace(/\/$/, "")
  try {
    const res = await fetch(`${baseUrl}/v1/config/snapshot`, {
      cache: "no-store",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
    })
    if (!res.ok) {
      throw new Error(`unexpected status ${res.status}`)
    }
    const data = await res.json()
    return normaliseSnapshot(data)
  } catch (error) {
    if (process.env.NODE_ENV !== "production") {
      console.error("[frontend] failed to fetch snapshot:", error)
    }
    throw error
  }
}
