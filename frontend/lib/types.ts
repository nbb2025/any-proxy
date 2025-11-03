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

export interface ConfigSnapshot {
  version: number
  generatedAt: string
  domains: DomainRoute[]
  tunnels: TunnelRoute[]
}
