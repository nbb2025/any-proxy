import type {
  AccessPolicy,
  Certificate,
  Condition,
  ConfigSnapshot,
  DomainRoute,
  EdgeNode,
  HeaderMutation,
  Matcher,
  NodeCategory,
  NodeGroup,
  PolicyScope,
  RewriteActions,
  RewriteRule,
  SSLPolicy,
  TunnelAgent,
  TunnelAgentService,
  TunnelGroup,
  TunnelRoute,
  Upstream,
  UpstreamOverride,
  URLRewrite,
  RouteListener,
} from "./types"

function resolveControlPlaneURL(): string {
  if (typeof window !== "undefined") {
    const override = (process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? "").trim()
    const isLocalOverride = /^https?:\/\/(localhost|127\.|0\.0\.0\.0)/i.test(override)
    if (override && !isLocalOverride) {
      return override
    }
    return window.location.origin
  }
  return (process.env.CONTROL_PLANE_API_URL ?? "").trim()
}


function httpError(res: Response, message: string): Error & { status: number } {
  const err = new Error(message) as Error & { status: number }
  err.status = res.status
  return err
}

function generateId(): string {
  if (typeof globalThis !== "undefined" && typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID()
  }
  return `id-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`
}

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
    id: String(raw?.id ?? generateId()),
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
    id: String(raw?.id ?? generateId()),
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
    id: String(raw?.id ?? generateId()),
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
    id: String(raw?.id ?? generateId()),
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

function normaliseNodeCategory(value: any): NodeCategory {
  const lowered = toStringValue(value)?.toLowerCase()
  switch (lowered) {
    case "cdn":
      return "cdn"
    case "tunnel":
    case "penetration":
      return "tunnel"
    case "waiting":
    case "pending":
    case "unassigned":
    default:
      return "waiting"
  }
}

function normaliseNodeGroup(raw: any): NodeGroup {
  return {
    id: String(raw?.id ?? generateId()),
    name: String(raw?.name ?? ""),
    category: normaliseNodeCategory(raw?.category),
    description: toStringValue(raw?.description),
    system: Boolean(raw?.system),
    createdAt: toStringValue(raw?.createdAt),
    updatedAt: toStringValue(raw?.updatedAt),
  }
}

function normaliseEdgeNode(raw: any): EdgeNode {
  return {
    id: String(raw?.id ?? ""),
    groupId: toStringValue(raw?.groupId) ?? "",
    category: normaliseNodeCategory(raw?.category),
    kind: toStringValue(raw?.kind) ?? "edge",
    name: toStringValue(raw?.name),
    hostname: toStringValue(raw?.hostname),
    addresses: toStringArray(raw?.addresses).filter((addr) => addr.length > 0),
    version: toStringValue(raw?.version),
    agentVersion: toStringValue(raw?.agentVersion),
    agentDesiredVersion: toStringValue(raw?.agentDesiredVersion),
    lastUpgradeAt: toStringValue(raw?.lastUpgradeAt),
    lastSeen: toStringValue(raw?.lastSeen),
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

function normaliseListenerArray(raw: any): RouteListener[] {
  if (!Array.isArray(raw)) {
    return []
  }
  return raw
    .map((item: any) => {
      const protocol = toStringValue(item?.protocol)?.toUpperCase() === "HTTPS" ? "HTTPS" : "HTTP"
      const portNumber = Number(item?.port ?? 0)
      return {
        protocol,
        port: Number.isFinite(portNumber) && portNumber > 0 ? portNumber : undefined,
      }
    })
    .filter((item) => item.protocol)
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
          displayName: toStringValue(raw.metadata.displayName),
          groupName: toStringValue(raw.metadata.groupName),
          remark: toStringValue(raw.metadata.remark),
          forwardMode: toStringValue(raw.metadata.forwardMode),
          loadBalancingAlgorithm: toStringValue(raw.metadata.loadBalancingAlgorithm),
          inboundListeners: normaliseListenerArray(raw.metadata.inboundListeners),
          outboundListeners: normaliseListenerArray(raw.metadata.outboundListeners),
        }
      : undefined,
    updatedAt: raw?.updatedAt ? String(raw.updatedAt) : undefined,
  }
}

function normaliseTunnel(raw: any): TunnelRoute {
  return {
    id: String(raw?.id ?? generateId()),
    groupId: String(raw?.groupId ?? ""),
    protocol: String(raw?.protocol ?? "tcp"),
    bindHost: String(raw?.bindHost ?? ""),
    bindPort: Number(raw?.bindPort ?? 0),
    bridgeBind: raw?.bridgeBind ? String(raw.bridgeBind) : undefined,
    bridgePort: raw?.bridgePort !== undefined ? Number(raw.bridgePort) : undefined,
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

function normaliseTunnelGroup(raw: any): TunnelGroup {
  return {
    id: String(raw?.id ?? generateId()),
    name: String(raw?.name ?? ""),
    description: toStringValue(raw?.description),
    listenAddress: String(raw?.listenAddress ?? ""),
    edgeNodeIds: toStringArray(raw?.edgeNodeIds),
    transports: toStringArray(raw?.transports),
    enableCompress: Boolean(raw?.enableCompress),
    createdAt: toStringValue(raw?.createdAt),
    updatedAt: toStringValue(raw?.updatedAt),
  }
}

function normaliseTunnelAgentService(raw: any): TunnelAgentService {
  return {
    id: String(raw?.id ?? generateId()),
    protocol: toStringValue(raw?.protocol)?.toLowerCase() ?? "tcp",
    localAddress: String(raw?.localAddress ?? "127.0.0.1"),
    localPort: Number(raw?.localPort ?? raw?.remotePort ?? 0),
    remotePort: Number(raw?.remotePort ?? 0),
    enableCompression: Boolean(raw?.enableCompression),
    description: toStringValue(raw?.description),
  }
}

function normaliseTunnelAgent(raw: any): TunnelAgent {
  return {
    id: String(raw?.id ?? generateId()),
    nodeId: String(raw?.nodeId ?? ""),
    groupId: String(raw?.groupId ?? ""),
    description: toStringValue(raw?.description),
    keyVersion: Number(raw?.keyVersion ?? 1),
    enabled: raw?.enabled !== false,
    services: Array.isArray(raw?.services) ? raw.services.map(normaliseTunnelAgentService) : [],
    createdAt: toStringValue(raw?.createdAt),
    updatedAt: toStringValue(raw?.updatedAt),
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

export async function fetchNodeGroups(token: string): Promise<NodeGroup[]> {
  const url = new URL("/v1/node-groups", resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `加载节点分组失败：${response.statusText}`)
  }
  const data = await response.json()
  return Array.isArray(data?.groups) ? data.groups.map(normaliseNodeGroup) : []
}

export interface TunnelGroupPayload {
  name: string
  description?: string
  listenAddress?: string
  edgeNodeIds?: string[]
  transports?: string[]
  enableCompress?: boolean
}

export async function fetchTunnelGroups(token: string): Promise<TunnelGroup[]> {
  const url = new URL("/v1/tunnel-groups", resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${token}` },
    credentials: "include",
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `加载隧道分组失败：${res.statusText}`)
  }
  const data = await res.json()
  return Array.isArray(data?.groups) ? data.groups.map(normaliseTunnelGroup) : []
}

export async function createTunnelGroupRequest(token: string, payload: TunnelGroupPayload): Promise<TunnelGroup> {
  const url = new URL("/v1/tunnel-groups", resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `创建隧道分组失败：${res.statusText}`)
  }
  const data = await res.json()
  return normaliseTunnelGroup(data?.group)
}

export async function updateTunnelGroupRequest(
  token: string,
  id: string,
  payload: TunnelGroupPayload,
): Promise<TunnelGroup> {
  const url = new URL(`/v1/tunnel-groups/${id}`, resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `更新隧道分组失败：${res.statusText}`)
  }
  const data = await res.json()
  return normaliseTunnelGroup(data?.group)
}

export async function deleteTunnelGroupRequest(token: string, id: string): Promise<void> {
  const url = new URL(`/v1/tunnel-groups/${id}`, resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
    credentials: "include",
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `删除隧道分组失败：${res.statusText}`)
  }
}

export interface TunnelAgentPayload {
  nodeId: string
  groupId: string
  description?: string
  enabled?: boolean
  rotateKey?: boolean
  services: Array<{
    id: string
    protocol?: string
    localAddress?: string
    localPort?: number
    remotePort: number
    enableCompression?: boolean
    description?: string
  }>
}

type TunnelAgentResponse = { agent: TunnelAgent; agentKey?: string }

export async function fetchTunnelAgents(token: string): Promise<TunnelAgent[]> {
  const url = new URL("/v1/tunnel-agents", resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${token}` },
    credentials: "include",
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `加载 Tunnel Agent 失败：${res.statusText}`)
  }
  const data = await res.json()
  return Array.isArray(data?.agents) ? data.agents.map(normaliseTunnelAgent) : []
}

export async function createTunnelAgentRequest(
  token: string,
  payload: TunnelAgentPayload,
): Promise<TunnelAgentResponse> {
  const url = new URL("/v1/tunnel-agents", resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `创建 Tunnel Agent 失败：${res.statusText}`)
  }
  const data = await res.json()
  return {
    agent: normaliseTunnelAgent(data?.agent),
    agentKey: toStringValue(data?.agentKey),
  }
}

export async function updateTunnelAgentRequest(
  token: string,
  id: string,
  payload: TunnelAgentPayload,
): Promise<TunnelAgentResponse> {
  const url = new URL(`/v1/tunnel-agents/${id}`, resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `更新 Tunnel Agent 失败：${res.statusText}`)
  }
  const data = await res.json()
  return {
    agent: normaliseTunnelAgent(data?.agent),
    agentKey: toStringValue(data?.agentKey),
  }
}

export async function deleteTunnelAgentRequest(token: string, id: string): Promise<void> {
  const url = new URL(`/v1/tunnel-agents/${id}`, resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` },
    credentials: "include",
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `删除 Tunnel Agent 失败：${res.statusText}`)
  }
}

export async function refreshTunnelAgentKeyRequest(token: string, id: string): Promise<string> {
  const url = new URL(`/v1/tunnel-agents/${id}/refresh-key`, resolveControlPlaneURL())
  const res = await fetch(url.toString(), {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    credentials: "include",
  })
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    throw httpError(res, detail?.error || `刷新密钥失败：${res.statusText}`)
  }
  const data = await res.json()
  const key = toStringValue(data?.agentKey)
  if (!key) {
    throw new Error("控制面未返回新的 agentKey")
  }
  return key
}

export interface NodeInventory {
  nodes: EdgeNode[]
  groups: NodeGroup[]
  version: number
}

export async function fetchNodeInventory(token: string): Promise<NodeInventory> {
  const url = new URL("/v1/nodes", resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
  })
  if (!response.ok) {
    throw httpError(response, `加载节点失败：${response.statusText}`)
  }

  const data = await response.json()
  const nodes = Array.isArray(data?.nodes) ? data.nodes.map(normaliseEdgeNode) : []
  const groups = Array.isArray(data?.groups) ? data.groups.map(normaliseNodeGroup) : []
  return {
    nodes,
    groups,
    version: Number(data?.version ?? 0),
  }
}

export interface AgentVersionListing {
  versions: string[]
  latestResolved?: string
}

export async function fetchAgentVersions(token: string): Promise<AgentVersionListing> {
  const url = new URL("/v1/agent-versions", resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
  })
  if (!response.ok) {
    throw httpError(response, `加载 Agent 版本列表失败：${response.statusText}`)
  }
  const data = await response.json()
  const rawList = Array.isArray(data?.versions) ? data.versions.map((item: any) => String(item ?? "").trim()) : []
  const seen = new Set<string>()
  const ordered: string[] = []
  const add = (value: string) => {
    if (!value || seen.has(value)) return
    seen.add(value)
    ordered.push(value)
  }
  add("latest")
  rawList.forEach(add)
  if (ordered.length === 0) {
    ordered.push("latest")
  }
  const latestResolved = typeof data?.latest === "string" ? data.latest.trim() : ""
  return { versions: ordered, latestResolved }
}

export async function createNodeGroupRequest(
  token: string,
  payload: { name: string; category: NodeCategory; description?: string },
): Promise<NodeGroup> {
  const url = new URL("/v1/node-groups", resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify({
      name: payload.name,
      category: payload.category,
      description: payload.description,
    }),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `创建分组失败：${response.statusText}`)
  }
  const data = await response.json()
  return normaliseNodeGroup(data?.group)
}

export async function updateNodeGroupRequest(
  token: string,
  id: string,
  payload: { name: string; description?: string },
): Promise<NodeGroup> {
  const url = new URL(`/v1/node-groups/${id}`, resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify({
      name: payload.name,
      description: payload.description,
    }),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `更新分组失败：${response.statusText}`)
  }
  const data = await response.json()
  return normaliseNodeGroup(data?.group)
}

export async function deleteNodeGroupRequest(token: string, id: string): Promise<void> {
  const url = new URL(`/v1/node-groups/${id}`, resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `删除分组失败：${response.statusText}`)
  }
}

export async function moveNodeToGroupRequest(token: string, nodeId: string, groupId: string | null): Promise<EdgeNode> {
  return updateNodeRequest(token, nodeId, { groupId })
}

export async function updateNodeRequest(
  token: string,
  nodeId: string,
  payload: {
    groupId?: string | null
    name?: string | null
    category?: NodeCategory | null
    agentDesiredVersion?: string | null
  },
): Promise<EdgeNode> {
  const url = new URL(`/v1/nodes/${nodeId}`, resolveControlPlaneURL())
  const body: Record<string, string> = {}
  if (payload.groupId !== undefined) {
    body.groupId = payload.groupId ?? ""
  }
  if (payload.name !== undefined) {
    body.name = payload.name ?? ""
  }
  if (payload.category !== undefined) {
    body.category = payload.category ?? ""
  }
  if (payload.agentDesiredVersion !== undefined) {
    body.agentDesiredVersion = payload.agentDesiredVersion ?? ""
  }

  if (Object.keys(body).length === 0) {
    throw new Error("未提供可更新的节点字段")
  }
  const response = await fetch(url.toString(), {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `更新节点失败：${response.statusText}`)
  }
  const data = await response.json()
  return normaliseEdgeNode(data?.node)
}

export async function deleteNodeRequest(token: string, nodeId: string): Promise<void> {
  const url = new URL(`/v1/nodes/${nodeId}`, resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `删除节点失败：${response.statusText}`)
  }
}

export async function updateNodesDesiredVersionRequest(
  token: string,
  payload: { nodeIds: string[]; agentDesiredVersion: string | null },
): Promise<{ updated: number }> {
  const url = new URL("/v1/nodes/desired-version", resolveControlPlaneURL())
  const body = {
    nodeIds: payload.nodeIds,
    agentDesiredVersion: payload.agentDesiredVersion ?? "",
  }
  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `批量更新版本失败：${response.statusText}`)
  }
  const data = await response.json()
  return { updated: Number(data?.updated ?? 0) }
}

export async function fetchSnapshot(token: string): Promise<ConfigSnapshot> {
  const base = resolveControlPlaneURL()
  if (!base) {
    throw new Error("control plane URL is not configured")
  }
  if (!token) {
    throw new Error("access token missing")
  }
  const baseUrl = base.replace(/\/$/, "")
  const snapshotUrl = new URL(`${baseUrl}/v1/config/snapshot`)
  snapshotUrl.searchParams.set("since", "-1")
  snapshotUrl.searchParams.set("_ts", Date.now().toString())

  try {
    const res = await fetch(snapshotUrl.toString(), {
      cache: "no-store",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
        "Cache-Control": "no-cache",
        Pragma: "no-cache",
      },
    })
    if (!res.ok) {
      const error = new Error(`unexpected status ${res.status}`) as Error & { status?: number }
      error.status = res.status
      throw error
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

export interface DomainUpstreamInput {
  address: string
  weight?: number
  maxFails?: number
  failTimeout?: string
  healthCheck?: string
  usePersistent?: boolean
}

export interface DomainRequestPayload {
  id?: string
  domain: string
  enableTls: boolean
  edgeNodes?: string[]
  upstreams: DomainUpstreamInput[]
  metadata?: {
    sticky?: boolean
    timeoutProxy?: string
    timeoutRead?: string
    timeoutSend?: string
    displayName?: string
    groupName?: string
  }
}

export async function createDomainRequest(token: string, payload: DomainRequestPayload): Promise<void> {
  const url = new URL("/v1/domains", resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(payload),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `创建应用代理失败：${response.statusText}`)
  }
}

export async function updateDomainRequest(token: string, payload: DomainRequestPayload): Promise<void> {
  const url = new URL("/v1/domains", resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
    body: JSON.stringify(payload),
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `更新应用代理失败：${response.statusText}`)
  }
}

export async function deleteDomainRequest(token: string, id: string): Promise<void> {
  const url = new URL(`/v1/domains/${id}`, resolveControlPlaneURL())
  const response = await fetch(url.toString(), {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    credentials: "include",
  })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}))
    throw httpError(response, detail?.error || `删除应用代理失败：${response.statusText}`)
  }
}
