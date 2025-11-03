package templates

import "time"

// EdgeTemplateData is rendered into nginx.conf for HTTP/S routing.
type EdgeTemplateData struct {
	Version     int64
	GeneratedAt time.Time
	NodeID      string
	Domains     []EdgeDomain
}

// EdgeDomain describes a single server block and its upstream cluster.
type EdgeDomain struct {
	Domain        string
	EnableTLS     bool
	AccountID     string
	UpstreamName  string
	Sticky        bool
	ProxyTimeout  string
	ReadTimeout   string
	SendTimeout   string
	EnablePersist bool
	Upstreams     []EdgeUpstream
}

// EdgeUpstream carries attributes for an upstream member.
type EdgeUpstream struct {
	Address       string
	Weight        int
	MaxFails      int
	FailTimeout   string
	UsePersistent bool
	HealthCheck   string
}

// TunnelTemplateData is rendered into stream.conf for TCP/UDP relay.
type TunnelTemplateData struct {
	Version     int64
	GeneratedAt time.Time
	NodeID      string
	Routes      []TunnelRoute
}

// TunnelRoute models a stream server block.
type TunnelRoute struct {
	Name             string
	Protocol         string
	ListenAddress    string
	IdleTimeout      string
	TargetAddress    string
	EnableProxyProto bool
}
