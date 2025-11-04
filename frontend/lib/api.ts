import { randomUUID } from "crypto"
import type {
  AccessPolicy,
  Certificate,
  Condition,
  ConfigSnapshot,
  DomainRoute,
  HeaderMutation,
  Matcher,
  PolicyScope,
  RewriteActions,
  RewriteRule,
  SSLPolicy,
  TunnelRoute,
  Upstream,
  UpstreamOverride,
  URLRewrite,
} from "./types"

const CONTROL_PLANE_URL = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? process.env.CONTROL_PLANE_URL ?? ""

function toNumber(value: unknown | undefined): number | undefined {
  if (value === null || value === undefined) return undefined
  const num = Number(value)
  return Number.isFinite(num) ? num : undefined
}

function toStringValue(value: unknown | undefined): string | undefined {
  if (value === null || value === undefined) return undefined
  const str = String(value)
  return str.length > 0 ? str : undefined
}

function toStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    return []
  }
  return raw.map((item) => String(item ?? ""))
}

function normaliseScope(raw: any): PolicyScope {
  return {
    mode: toStringValue(raw?.mode)?.toLowerCase() ?? "any",
    resources: toStringArray(raw?.resources),
    tags: toStringArray(raw?.tags),
  }
}

function normaliseMatchers(raw: any): Matcher[] {
  if (!Array.isArray(raw)) {
    return []
  }
  return raw.map((matcher) => ({
    type: String(matcher?.type ?? ""),
    key: toStringValue(matcher?.key),
    operator: toStringValue(matcher?.operator),
    values: toStringArray(matcher?.values),
  }))
}

function normaliseCondition(raw: any): Condition {
  const mode = toStringValue(raw?.mode)?.toLowerCase() ?? "any"
  return {
    mode,
    matchers: mode === "matchers" ? normaliseMatchers(raw?.matchers) : [],
  }
}

function normaliseCertificate(raw: any): Certificate {
  return {
    id: String(raw?.id ?? randomUUID()),
    name: String(raw?.name ?? ""),
    description: toStringValue(raw?.description),
    domains: toStringArray(raw?.domains),
    issuer: toStringValue(raw?.issuer),
    notBefore: toStringValue(raw?.notBefore),
    notAfter: toStringValue(raw?.notAfter),
    status: toStringValue(raw?.status),
    managed: Boolean(raw?.managed),
    managedProvider: toStringValue(raw?.managedProvider),
    createdAt: toStringValue(raw?.createdAt),
    updatedAt: toStringValue(raw?.updatedAt),
  }
}

function normaliseSSLPolicy(raw: any): SSLPolicy {
  return {
    id: String(raw?.id ?? randomUUID()),
    name: String(raw?.name ?? ""),
    description: toStringValue(raw?.description),
    scope: normaliseScope(raw?.scope),
    condition: normaliseCondition(raw?.condition),
    certificateId: toStringValue(raw?.certificateId),
    enforceHttps: Boolean(raw?.enforceHttps),
    enableHsts: Boolean(raw?.enableHsts),
    hstsMaxAge: toStringValue(raw?.hstsMaxAge),
    hstsIncludeSubdomains: Boolean(raw?.hstsIncludeSubdomains),
    hstsPreload: Boolean(raw?.hstsPreload),
    minTlsVersion: toStringValue(raw?.minTlsVersion),
    enableOcspStapling: Boolean(raw?.enableOcspStapling),
    clientAuth: Boolean(raw?.clientAuth),
    clientCaIds: toStringArray(raw?.clientCaIds),
    createdAt: toStringValue(raw?.createdAt),
    updatedAt: toStringValue(raw?.updatedAt),
  }
}

function normaliseAccessPolicy(raw: any): AccessPolicy {
  const action = toStringValue(raw?.action)?.toLowerCase() ?? "allow"
  return {
    id: String(raw?.id ?? randomUUID()),
    name: String(raw?.name ?? ""),
    description: toStringValue(raw?.description),
    scope: normaliseScope(raw?.scope),
    condition: normaliseCondition(raw?.condition),
    action: (action as AccessPolicy["action"]) ?? "allow",
    responseCode: toNumber(raw?.responseCode),
    redirectUrl: toStringValue(raw?.redirectUrl),
    createdAt: toStringValue(raw?.createdAt),
    updatedAt: toStringValue(raw?.updatedAt),
  }
}

function normaliseURLRewrite(raw: any): URLRewrite | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined
  }
  const url: URLRewrite = {}
  const mode = toStringValue(raw?.mode)
  if (mode) url.mode = mode
  const path = toStringValue(raw?.path)
  if (path) url.path = path
  const query = toStringValue(raw?.query)
  if (query) url.query = query
  if (Object.keys(url).length === 0) {
    return undefined
  }
  return url
}

function normaliseHeaderMutation(raw: any): HeaderMutation {
  return {
    operation: String(raw?.operation ?? ""),
    name: String(raw?.name ?? ""),
    value: toStringValue(raw?.value),
  }
}

function normaliseUpstreamOverride(raw: any): UpstreamOverride | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined
  }
  const override: UpstreamOverride = {
    passHostHeader: Boolean(raw?.passHostHeader),
  }
  const upstreamHost = toStringValue(raw?.upstreamHost)
  if (upstreamHost) override.upstreamHost = upstreamHost
  const scheme = toStringValue(raw?.scheme)
  if (scheme) override.scheme = scheme
  const connectTimeout = toStringValue(raw?.connectTimeout)
  if (connectTimeout) override.connectTimeout = connectTimeout
  const readTimeout = toStringValue(raw?.readTimeout)
  if (readTimeout) override.readTimeout = readTimeout
  const sendTimeout = toStringValue(raw?.sendTimeout)
  if (sendTimeout) override.sendTimeout = sendTimeout
  return override
}

function normaliseRewriteActions(raw: any): RewriteActions {
  const actions: RewriteActions = {}
  const sni = toStringValue(raw?.sniOverride)
  if (sni) actions.sniOverride = sni
  const host = toStringValue(raw?.hostOverride)
  if (host) actions.hostOverride = host
  const url = normaliseURLRewrite(raw?.url)
  if (url) actions.url = url
  if (Array.isArray(raw?.headers)) {
    actions.headers = raw.headers.map(normaliseHeaderMutation)
  }
  const upstream = normaliseUpstreamOverride(raw?.upstream)
  if (upstream) actions.upstream = upstream
  return actions
}

function normaliseRewriteRule(raw: any): RewriteRule {
  return {
    id: String(raw?.id ?? randomUUID()),
    name: String(raw?.name ?? ""),
    description: toStringValue(raw?.description),
    scope: normaliseScope(raw?.scope),
    condition: normaliseCondition(raw?.condition),
    actions: normaliseRewriteActions(raw?.actions),
    priority: Number(raw?.priority ?? 0),
    createdAt: toStringValue(raw?.createdAt),
    updatedAt: toStringValue(raw?.updatedAt),
  }
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
  const certificates = Array.isArray(raw?.certificates) ? raw.certificates.map(normaliseCertificate) : []
  const sslPolicies = Array.isArray(raw?.sslPolicies) ? raw.sslPolicies.map(normaliseSSLPolicy) : []
  const accessPolicies = Array.isArray(raw?.accessPolicies) ? raw.accessPolicies.map(normaliseAccessPolicy) : []
  const rewriteRules = Array.isArray(raw?.rewriteRules) ? raw.rewriteRules.map(normaliseRewriteRule) : []
  return {
    version: Number(raw?.version ?? 0),
    generatedAt: raw?.generatedAt ? String(raw.generatedAt) : new Date().toISOString(),
    domains,
    tunnels,
    certificates,
    sslPolicies,
    accessPolicies,
    rewriteRules,
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
