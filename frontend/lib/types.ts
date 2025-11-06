export interface Upstream {
  address: string
  weight?: number
  maxFails?: number
  failTimeout?: number
  healthCheck?: string
  usePersistent?: boolean
}

export interface RouteMeta {
  sticky?: boolean
  timeoutProxy?: number
  timeoutRead?: number
  timeoutSend?: number
}

export interface DomainRoute {
  id: string
  domain: string
  enableTls: boolean
  upstreams: Upstream[]
  edgeNodes: string[]
  metadata?: RouteMeta
  updatedAt?: string
}

export interface TunnelMeta {
  enableProxyProtocol?: boolean
  description?: string
}

export interface TunnelRoute {
  id: string
  protocol: string
  bindHost: string
  bindPort: number
  target: string
  nodeIds: string[]
  idleTimeout?: number
  metadata?: TunnelMeta
  updatedAt?: string
}

export interface Certificate {
  id: string
  name: string
  description?: string
  domains: string[]
  issuer?: string
  notBefore?: string
  notAfter?: string
  status?: string
  managed: boolean
  managedProvider?: string
  createdAt?: string
  updatedAt?: string
}

export interface PolicyScope {
  mode: string
  resources: string[]
  tags: string[]
}

export interface Matcher {
  type: string
  key?: string
  operator?: string
  values?: string[]
}

export interface Condition {
  mode: string
  matchers: Matcher[]
}

export interface SSLPolicy {
  id: string
  name: string
  description?: string
  scope: PolicyScope
  condition: Condition
  certificateId?: string
  enforceHttps: boolean
  enableHsts: boolean
  hstsMaxAge?: string
  hstsIncludeSubdomains?: boolean
  hstsPreload?: boolean
  minTlsVersion?: string
  enableOcspStapling: boolean
  clientAuth: boolean
  clientCaIds: string[]
  createdAt?: string
  updatedAt?: string
}

export interface AccessPolicy {
  id: string
  name: string
  description?: string
  scope: PolicyScope
  condition: Condition
  action: "allow" | "deny" | string
  responseCode?: number
  redirectUrl?: string
  createdAt?: string
  updatedAt?: string
}

export interface URLRewrite {
  mode?: string
  path?: string
  query?: string
}

export interface HeaderMutation {
  operation: string
  name: string
  value?: string
}

export interface UpstreamOverride {
  passHostHeader: boolean
  upstreamHost?: string
  scheme?: string
  connectTimeout?: string
  readTimeout?: string
  sendTimeout?: string
}

export interface RewriteActions {
  sniOverride?: string
  hostOverride?: string
  url?: URLRewrite
  headers?: HeaderMutation[]
  upstream?: UpstreamOverride
}

export interface RewriteRule {
  id: string
  name: string
  description?: string
  scope: PolicyScope
  condition: Condition
  actions: RewriteActions
  priority: number
  createdAt?: string
  updatedAt?: string
}

export type NodeCategory = "waiting" | "cdn" | "tunnel"

export interface NodeGroup {
  id: string
  name: string
  category: NodeCategory
  description?: string
  system?: boolean
  createdAt?: string
  updatedAt?: string
}

export interface EdgeNode {
  id: string
  groupId: string
  category: NodeCategory
  kind: string
  hostname?: string
  addresses: string[]
  version?: string
  lastSeen?: string
  createdAt?: string
  updatedAt?: string
}

export interface ConfigSnapshot {
  version: number
  generatedAt: string
  domains: DomainRoute[]
  tunnels: TunnelRoute[]
  certificates: Certificate[]
  sslPolicies: SSLPolicy[]
  accessPolicies: AccessPolicy[]
  rewriteRules: RewriteRule[]
}
