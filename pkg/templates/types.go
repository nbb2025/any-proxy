package templates

import "time"

// EdgeTemplateData is rendered into nginx.conf for HTTP/S routing.
type EdgeTemplateData struct {
	Version        int64
	GeneratedAt    time.Time
	NodeID         string
	Domains        []EdgeDomain
	Certificates   map[string]CertificateMaterial
	SSLPolicies    []SSLPolicy
	AccessPolicies []AccessPolicy
	RewriteRules   []RewriteRule
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

// CertificateMaterial holds paths for TLS assets.
type CertificateMaterial struct {
	CertificatePath string
	KeyPath         string
}

// SSLPolicy represents TLS behaviour applied to a domain.
type SSLPolicy struct {
	ID                    string
	Name                  string
	Description           string
	Scope                 PolicyScope
	EnforceHTTPS          bool
	EnableHSTS            bool
	HSTSMaxAge            time.Duration
	HSTSIncludeSubdomains bool
	HSTSPreload           bool
	MinTLSVersion         string
	EnableOCSPStapling    bool
	ClientAuth            bool
	ClientCAPaths         []string
}

// AccessPolicy controls request admission.
type AccessPolicy struct {
	ID           string
	Name         string
	Description  string
	Scope        PolicyScope
	Matchers     []Matcher
	Action       string
	ResponseCode int
	RedirectURL  string
}

// RewriteRule describes origin request mutations.
type RewriteRule struct {
	ID          string
	Name        string
	Description string
	Scope       PolicyScope
	Matchers    []Matcher
	Actions     RewriteActions
	Priority    int
}

// PolicyScope indicates target resources/tags.
type PolicyScope struct {
	Mode      string
	Resources []string
	Tags      []string
}

// Matcher represents a single condition.
type Matcher struct {
	Type     string
	Key      string
	Operator string
	Values   []string
}

// RewriteActions describes supported origin rewrites.
type RewriteActions struct {
	SNIOverride  string
	HostOverride string
	URL          URLRewrite
	Headers      []HeaderMutation
	Upstream     *UpstreamOverride
}

// URLRewrite modifies path/query components.
type URLRewrite struct {
	Mode  string
	Path  string
	Query string
}

// HeaderMutation adjusts headers before proxying.
type HeaderMutation struct {
	Operation string
	Name      string
	Value     string
}

// UpstreamOverride reconfigures upstream behaviour.
type UpstreamOverride struct {
	PassHostHeader bool
	UpstreamHost   string
	Scheme         string
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	SendTimeout    time.Duration
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
