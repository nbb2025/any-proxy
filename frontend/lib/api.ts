import { randomUUID } from "crypto"
import type { ConfigSnapshot, DomainRoute, TunnelRoute, Upstream } from "./types"

const CONTROL_PLANE_URL =
  process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? process.env.CONTROL_PLANE_URL ?? "http://127.0.0.1:8080"

const FALLBACK_SNAPSHOT: ConfigSnapshot = {
  version: 1,
  generatedAt: new Date().toISOString(),
  domains: [
    {
      id: "demo-edge",
      domain: "demo.any-proxy.local",
      enableTls: false,
      edgeNodes: ["edge-a", "edge-b"],
      upstreams: [
        { address: "10.0.10.15:8080", weight: 1 },
        { address: "10.0.10.16:8080", weight: 1, usePersistent: true },
      ],
      metadata: {
        sticky: true,
        timeoutProxy: 5_000_000_000,
        timeoutRead: 30_000_000_000,
        timeoutSend: 30_000_000_000,
      },
    },
  ],
  tunnels: [
    {
      id: "ssh-demo",
      protocol: "tcp",
      bindHost: "0.0.0.0",
      bindPort: 2222,
      target: "127.0.0.1:22",
      nodeIds: ["tunnel-a", "tunnel-b"],
      idleTimeout: 120_000_000_000,
      metadata: {
        enableProxyProtocol: false,
        description: "SSH relay",
      },
    },
  ],
}

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

export async function fetchSnapshot(): Promise<ConfigSnapshot> {
  const baseUrl = CONTROL_PLANE_URL.replace(/\/$/, "")
  try {
    const res = await fetch(`${baseUrl}/v1/config/snapshot`, {
      cache: "no-store",
      headers: {
        Accept: "application/json",
      },
    })
    if (!res.ok) {
      throw new Error(`unexpected status ${res.status}`)
    }
    const data = await res.json()
    return normaliseSnapshot(data)
  } catch (error) {
    if (process.env.NODE_ENV !== "production") {
      console.warn("[frontend] failed to fetch snapshot, fallback to sample data:", error)
    }
    return { ...FALLBACK_SNAPSHOT, generatedAt: new Date().toISOString() }
  }
}

