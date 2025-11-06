package configstore

const (
	defaultWaitingGroupID = "group-waiting-default"
	defaultCDNGroupID     = "group-cdn-default"
	defaultTunnelGroupID  = "group-tunnel-default"
)

// defaultSystemGroupMeta maps a node category to the canonical system group ID/name.
func defaultSystemGroupMeta(category NodeCategory) (id, name string) {
	switch category {
	case NodeCategoryCDN:
		return defaultCDNGroupID, "默认 CDN 分组"
	case NodeCategoryTunnel:
		return defaultTunnelGroupID, "默认内网穿透分组"
	default:
		return defaultWaitingGroupID, "待分组"
	}
}
