package configstore

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PGStore persists management-plane data (nodes, groups, tunnel metadata) in PostgreSQL.
type PGStore struct {
	db    *gorm.DB
	clock func() time.Time
}

// PGOption customises PGStore behaviour.
type PGOption func(*PGStore)

// WithPGClock overrides the time source, useful for tests.
func WithPGClock(clock func() time.Time) PGOption {
	return func(store *PGStore) {
		if clock != nil {
			store.clock = clock
		}
	}
}

// NewPGStore wires a Postgres-backed management store using the supplied gorm DB handle.
func NewPGStore(db *gorm.DB, opts ...PGOption) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("pgstore: db handle is nil")
	}
	store := &PGStore{
		db:    db,
		clock: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(store)
		}
	}
	if err := store.autoMigrate(); err != nil {
		return nil, err
	}
	if err := store.ensureSystemGroups(context.Background()); err != nil {
		return nil, err
	}
	return store, nil
}

// ManagementState captures all PG-backed resources for syncing to etcd.
type ManagementState struct {
	NodeGroups   []NodeGroup
	Nodes        []EdgeNode
	TunnelGroups []TunnelGroup
	TunnelAgents []TunnelAgent
}

// ExportState returns the full management dataset, sorted for deterministic replication.
func (p *PGStore) ExportState(ctx context.Context) (ManagementState, error) {
	var (
		groupModels []nodeGroupModel
		nodeModels  []edgeNodeModel
		tgModels    []tunnelGroupModel
		taModels    []tunnelAgentModel
		state       ManagementState
	)
	if err := p.withCtx(ctx).Order("created_at ASC, id ASC").Find(&groupModels).Error; err != nil {
		return ManagementState{}, err
	}
	if err := p.withCtx(ctx).Order("created_at ASC, id ASC").Find(&nodeModels).Error; err != nil {
		return ManagementState{}, err
	}
	if err := p.withCtx(ctx).Order("created_at ASC, id ASC").Find(&tgModels).Error; err != nil {
		return ManagementState{}, err
	}
	if err := p.withCtx(ctx).Order("created_at ASC, id ASC").Find(&taModels).Error; err != nil {
		return ManagementState{}, err
	}
	state.NodeGroups = make([]NodeGroup, 0, len(groupModels))
	for _, model := range groupModels {
		state.NodeGroups = append(state.NodeGroups, model.toEntity())
	}
	state.Nodes = make([]EdgeNode, 0, len(nodeModels))
	for _, model := range nodeModels {
		state.Nodes = append(state.Nodes, model.toEntity())
	}
	state.TunnelGroups = make([]TunnelGroup, 0, len(tgModels))
	for _, model := range tgModels {
		state.TunnelGroups = append(state.TunnelGroups, model.toEntity())
	}
	state.TunnelAgents = make([]TunnelAgent, 0, len(taModels))
	for _, model := range taModels {
		state.TunnelAgents = append(state.TunnelAgents, model.toEntity())
	}
	return state, nil
}

// UpsertNodeGroup creates or updates a logical node group.
func (p *PGStore) UpsertNodeGroup(group NodeGroup) (NodeGroup, error) {
	group.Name = strings.TrimSpace(group.Name)
	if group.Name == "" {
		return NodeGroup{}, ErrInvalidGroup
	}
	switch group.Category {
	case NodeCategoryWaiting, NodeCategoryCDN, NodeCategoryTunnel:
	default:
		return NodeGroup{}, ErrInvalidGroup
	}

	now := p.now()
	group.UpdatedAt = now

	err := p.db.Transaction(func(tx *gorm.DB) error {
		var existing nodeGroupModel
		if group.ID != "" {
			if err := tx.Where("id = ?", group.ID).Take(&existing).Error; err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
			}
		}
		if group.ID == "" {
			group.ID = uuid.NewString()
			group.CreatedAt = now
		} else if existing.ID != "" {
			if existing.System && existing.Category != string(group.Category) {
				return ErrProtectedGroup
			}
			if group.CreatedAt.IsZero() {
				group.CreatedAt = existing.CreatedAt
			}
			if existing.System {
				group.System = true
			}
		} else if group.CreatedAt.IsZero() {
			group.CreatedAt = now
		}
		if defaultID, _ := defaultSystemGroupMeta(group.Category); group.ID == defaultID {
			group.System = true
		}
		model := nodeGroupModelFromEntity(group)
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "category", "description", "system", "updated_at"}),
		}).Create(&model).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return NodeGroup{}, err
	}
	return group, nil
}

// DeleteNodeGroup removes a group and reassigns members back to the waiting pool. Returns reassigned nodes.
func (p *PGStore) DeleteNodeGroup(id string) ([]EdgeNode, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrGroupNotFound
	}
	now := p.now()
	var reassigned []EdgeNode

	err := p.db.Transaction(func(tx *gorm.DB) error {
		var model nodeGroupModel
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).Take(&model).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrGroupNotFound
			}
			return err
		}
		if model.System {
			return ErrProtectedGroup
		}

		waiting, err := p.ensureSystemGroupTx(tx, NodeCategoryWaiting)
		if err != nil {
			return err
		}

		var nodes []edgeNodeModel
		if err := tx.Where("group_id = ?", id).Find(&nodes).Error; err != nil {
			return err
		}
		if len(nodes) > 0 {
			if err := tx.Model(&edgeNodeModel{}).
				Where("group_id = ?", id).
				Updates(map[string]any{
					"group_id":   waiting.ID,
					"category":   waiting.Category,
					"updated_at": now,
				}).Error; err != nil {
				return err
			}
			reassigned = make([]EdgeNode, 0, len(nodes))
			for _, node := range nodes {
				entity := node.toEntity()
				entity.GroupID = waiting.ID
				entity.Category = waiting.Category
				entity.UpdatedAt = now
				reassigned = append(reassigned, entity)
			}
		}

		if err := tx.Delete(&nodeGroupModel{ID: id}).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return reassigned, nil
}

// RegisterOrUpdateNode persists agent metadata reported by edge/tunnel nodes.
// The returned boolean indicates whether persistent data actually changed.
func (p *PGStore) RegisterOrUpdateNode(reg NodeRegistration) (EdgeNode, bool, error) {
	nodeID := strings.TrimSpace(reg.ID)
	if nodeID == "" {
		return EdgeNode{}, false, ErrNodeNotFound
	}
	now := p.now()
	addresses := uniqueStrings(reg.Addresses)

	var result EdgeNode
	changed := false
	err := p.db.Transaction(func(tx *gorm.DB) error {
		group, err := p.resolveGroupForRegistrationTx(tx, reg.GroupID, reg.Category)
		if err != nil {
			return err
		}

		var model edgeNodeModel
		if err := tx.Where("id = ?", nodeID).Take(&model).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}
		node := model.toEntity()
		if node.ID == "" {
			node.ID = nodeID
			node.CreatedAt = now
		}

		if model.ID == "" {
			changed = true
		}

		if node.GroupID != group.ID {
			node.GroupID = group.ID
			node.Category = group.Category
			changed = true
		}

		if name := strings.TrimSpace(reg.Name); name != "" && name != node.Name {
			node.Name = name
			changed = true
		}
		if kind := strings.TrimSpace(reg.Kind); kind != "" && kind != node.Kind {
			node.Kind = kind
			changed = true
		} else if node.Kind == "" {
			node.Kind = "edge"
			changed = true
		}
		if host := strings.TrimSpace(reg.Hostname); host != "" && host != node.Hostname {
			node.Hostname = host
			changed = true
		}
		if len(addresses) > 0 && !equalStringSlices(node.Addresses, addresses) {
			node.Addresses = addresses
			changed = true
		}
		if ver := strings.TrimSpace(reg.Version); ver != "" && ver != node.Version {
			node.Version = ver
			changed = true
		}
		if agentVer := strings.TrimSpace(reg.AgentVersion); agentVer != "" && agentVer != node.AgentVersion {
			node.AgentVersion = agentVer
			changed = true
		}
		if hash := strings.TrimSpace(reg.NodeKeyHash); hash != "" {
			keyChanged := false
			if hash != node.NodeKeyHash {
				node.NodeKeyHash = hash
				keyChanged = true
				changed = true
			}
			if reg.NodeKeyVersion > 0 && reg.NodeKeyVersion != node.NodeKeyVersion {
				node.NodeKeyVersion = reg.NodeKeyVersion
				changed = true
			} else if node.NodeKeyVersion == 0 && keyChanged {
				node.NodeKeyVersion = 1
				changed = true
			}
		}

		node.LastSeen = now
		node.UpdatedAt = now
		if node.AgentDesiredVersion != "" && node.AgentVersion != "" && node.AgentDesiredVersion == node.AgentVersion {
			node.AgentDesiredVersion = ""
			node.LastUpgradeAt = now
			changed = true
		}

		entityModel := edgeNodeModelFromEntity(node)
		if err := tx.Save(&entityModel).Error; err != nil {
			return err
		}
		result = node
		return nil
	})
	if err != nil {
		return EdgeNode{}, false, err
	}
	return result, changed, nil
}

// UpdateNode mutates persisted node metadata.
func (p *PGStore) UpdateNode(nodeID string, update NodeUpdate) (EdgeNode, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return EdgeNode{}, ErrNodeNotFound
	}

	var result EdgeNode
	err := p.db.Transaction(func(tx *gorm.DB) error {
		var model edgeNodeModel
		if err := tx.Where("id = ?", nodeID).Take(&model).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNodeNotFound
			}
			return err
		}
		node := model.toEntity()
		changed := false

		if update.GroupID != nil {
			targetID := strings.TrimSpace(*update.GroupID)
			var group NodeGroup
			var err error
			if targetID == "" {
				group, err = p.ensureSystemGroupTx(tx, NodeCategoryWaiting)
			} else {
				group, err = p.getNodeGroupTx(tx, targetID)
			}
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrGroupNotFound
				}
				return err
			}
			if node.GroupID != group.ID {
				node.GroupID = group.ID
				node.Category = group.Category
				changed = true
			}
		}
		if update.Name != nil {
			name := strings.TrimSpace(*update.Name)
			if node.Name != name {
				node.Name = name
				changed = true
			}
		}
		if update.Category != nil {
			group, err := p.ensureSystemGroupTx(tx, *update.Category)
			if err != nil {
				return err
			}
			if node.Category != *update.Category || node.GroupID != group.ID {
				node.Category = *update.Category
				node.GroupID = group.ID
				changed = true
			}
		}
		if update.AgentDesiredVersion != nil {
			desired := strings.TrimSpace(*update.AgentDesiredVersion)
			if node.AgentDesiredVersion != desired {
				node.AgentDesiredVersion = desired
				changed = true
			}
		}

		if !changed {
			result = node
			return nil
		}
		node.UpdatedAt = p.now()
		entityModel := edgeNodeModelFromEntity(node)
		if err := tx.Save(&entityModel).Error; err != nil {
			return err
		}
		result = node
		return nil
	})
	if err != nil {
		return EdgeNode{}, err
	}
	return result, nil
}

// DeleteNode removes a node definition.
func (p *PGStore) DeleteNode(nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ErrNodeNotFound
	}
	return p.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Delete(&edgeNodeModel{ID: nodeID})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNodeNotFound
		}
		return nil
	})
}

// UpsertTunnelGroup creates or updates tunnel ingress metadata.
func (p *PGStore) UpsertTunnelGroup(group TunnelGroup) (TunnelGroup, error) {
	group.Name = strings.TrimSpace(group.Name)
	if group.Name == "" {
		return TunnelGroup{}, ErrInvalidTunnelGroup
	}
	group.ListenAddress = strings.TrimSpace(group.ListenAddress)
	if group.ListenAddress == "" {
		group.ListenAddress = ":4433"
	}
	group.EdgeNodeIDs = dedupeStrings(group.EdgeNodeIDs)
	group.Transports = normalizeTransports(group.Transports)

	now := p.now()
	group.UpdatedAt = now

	err := p.db.Transaction(func(tx *gorm.DB) error {
		var existing tunnelGroupModel
		if group.ID != "" {
			if err := tx.Where("id = ?", group.ID).Take(&existing).Error; err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
			}
		}
		if group.ID == "" {
			group.ID = uuid.NewString()
			group.CreatedAt = now
		} else if existing.ID != "" {
			if group.CreatedAt.IsZero() {
				group.CreatedAt = existing.CreatedAt
			}
		} else if group.CreatedAt.IsZero() {
			group.CreatedAt = now
		}

		model := tunnelGroupModelFromEntity(group)
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "description", "listen_address", "edge_node_ids", "transports", "enable_compress", "updated_at"}),
		}).Create(&model).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return TunnelGroup{}, err
	}
	return group, nil
}

// DeleteTunnelGroup removes a tunnel group if unused.
func (p *PGStore) DeleteTunnelGroup(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrTunnelGroupNotFound
	}
	return p.db.Transaction(func(tx *gorm.DB) error {
		var model tunnelGroupModel
		if err := tx.Where("id = ?", id).Take(&model).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrTunnelGroupNotFound
			}
			return err
		}
		var count int64
		if err := tx.Model(&tunnelAgentModel{}).Where("group_id = ?", id).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrTunnelGroupInUse
		}
		if err := tx.Delete(&tunnelGroupModel{ID: id}).Error; err != nil {
			return err
		}
		return nil
	})
}

// UpsertTunnelAgent creates or updates a tunnel agent definition.
func (p *PGStore) UpsertTunnelAgent(agent TunnelAgent) (TunnelAgent, error) {
	agent.NodeID = strings.TrimSpace(agent.NodeID)
	agent.GroupID = strings.TrimSpace(agent.GroupID)
	agent.KeyHash = strings.TrimSpace(agent.KeyHash)
	if agent.NodeID == "" || agent.GroupID == "" || agent.KeyHash == "" {
		return TunnelAgent{}, ErrInvalidTunnelAgent
	}
	agent.Services = normalizeServices(agent.Services)

	now := p.now()
	agent.UpdatedAt = now

	err := p.db.Transaction(func(tx *gorm.DB) error {
		if _, err := p.getTunnelGroupTx(tx, agent.GroupID); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrTunnelGroupNotFound
			}
			return err
		}
		var existing tunnelAgentModel
		if agent.ID != "" {
			if err := tx.Where("id = ?", agent.ID).Take(&existing).Error; err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
			}
		}
		if agent.ID == "" {
			agent.ID = uuid.NewString()
			agent.CreatedAt = now
			if agent.KeyVersion == 0 {
				agent.KeyVersion = 1
			}
		} else if existing.ID != "" {
			if agent.CreatedAt.IsZero() {
				agent.CreatedAt = existing.CreatedAt
			}
			if agent.KeyVersion == 0 {
				agent.KeyVersion = existing.KeyVersion
			}
			if agent.KeyHash == "" {
				agent.KeyHash = existing.KeyHash
			}
		} else if agent.CreatedAt.IsZero() {
			agent.CreatedAt = now
			if agent.KeyVersion == 0 {
				agent.KeyVersion = 1
			}
		}

		model := tunnelAgentModelFromEntity(agent)
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{"node_id", "group_id", "description", "key_hash", "key_version", "enabled", "services", "updated_at"}),
		}).Create(&model).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return TunnelAgent{}, err
	}
	return agent, nil
}

// DeleteTunnelAgent removes a tunnel agent definition.
func (p *PGStore) DeleteTunnelAgent(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrTunnelAgentNotFound
	}
	return p.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Delete(&tunnelAgentModel{ID: id})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrTunnelAgentNotFound
		}
		return nil
	})
}

func (p *PGStore) autoMigrate() error {
	return p.db.AutoMigrate(
		&nodeGroupModel{},
		&edgeNodeModel{},
		&tunnelGroupModel{},
		&tunnelAgentModel{},
	)
}

func (p *PGStore) ensureSystemGroups(ctx context.Context) error {
	return p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, category := range []NodeCategory{NodeCategoryWaiting, NodeCategoryCDN, NodeCategoryTunnel} {
			id, name := defaultSystemGroupMeta(category)
			var existing nodeGroupModel
			err := tx.Where("id = ?", id).Take(&existing).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				now := p.now()
				model := nodeGroupModel{
					ID:        id,
					Name:      name,
					Category:  string(category),
					System:    true,
					CreatedAt: now,
					UpdatedAt: now,
				}
				if err := tx.Create(&model).Error; err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *PGStore) ensureSystemGroupTx(tx *gorm.DB, category NodeCategory) (NodeGroup, error) {
	id, name := defaultSystemGroupMeta(category)
	var model nodeGroupModel
	if err := tx.Where("id = ?", id).Take(&model).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			now := p.now()
			model = nodeGroupModel{
				ID:        id,
				Name:      name,
				Category:  string(category),
				System:    true,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := tx.Create(&model).Error; err != nil {
				return NodeGroup{}, err
			}
		} else {
			return NodeGroup{}, err
		}
	}
	return model.toEntity(), nil
}

func (p *PGStore) getNodeGroupTx(tx *gorm.DB, id string) (NodeGroup, error) {
	var model nodeGroupModel
	if err := tx.Where("id = ?", id).Take(&model).Error; err != nil {
		return NodeGroup{}, err
	}
	return model.toEntity(), nil
}

func (p *PGStore) getTunnelGroupTx(tx *gorm.DB, id string) (TunnelGroup, error) {
	var model tunnelGroupModel
	if err := tx.Where("id = ?", id).Take(&model).Error; err != nil {
		return TunnelGroup{}, err
	}
	return model.toEntity(), nil
}

func (p *PGStore) resolveGroupForRegistrationTx(tx *gorm.DB, groupID string, category NodeCategory) (NodeGroup, error) {
	if id := strings.TrimSpace(groupID); id != "" {
		group, err := p.getNodeGroupTx(tx, id)
		if err == nil {
			return group, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return NodeGroup{}, err
		}
		if category != "" {
			return p.ensureSystemGroupTx(tx, category)
		}
		return p.ensureSystemGroupTx(tx, NodeCategoryWaiting)
	}
	if category != "" {
		return p.ensureSystemGroupTx(tx, category)
	}
	return p.ensureSystemGroupTx(tx, NodeCategoryWaiting)
}

func (p *PGStore) withCtx(ctx context.Context) *gorm.DB {
	if ctx == nil {
		ctx = context.Background()
	}
	return p.db.WithContext(ctx)
}

func (p *PGStore) now() time.Time {
	if p.clock != nil {
		return p.clock()
	}
	return time.Now().UTC()
}

type nodeGroupModel struct {
	ID          string `gorm:"primaryKey;size:191"`
	Name        string `gorm:"not null"`
	Category    string `gorm:"not null"`
	Description string
	System      bool      `gorm:"not null;default:false"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time `gorm:"not null"`
}

func (nodeGroupModel) TableName() string { return "node_groups" }

func (m nodeGroupModel) toEntity() NodeGroup {
	return NodeGroup{
		ID:          m.ID,
		Name:        m.Name,
		Category:    NodeCategory(m.Category),
		Description: m.Description,
		System:      m.System,
		CreatedAt:   m.CreatedAt.UTC(),
		UpdatedAt:   m.UpdatedAt.UTC(),
	}
}

func nodeGroupModelFromEntity(group NodeGroup) nodeGroupModel {
	return nodeGroupModel{
		ID:          group.ID,
		Name:        group.Name,
		Category:    string(group.Category),
		Description: group.Description,
		System:      group.System,
		CreatedAt:   group.CreatedAt.UTC(),
		UpdatedAt:   group.UpdatedAt.UTC(),
	}
}

type stringSliceJSON []string

func (s stringSliceJSON) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal([]string(s))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *stringSliceJSON) Scan(value any) error {
	if value == nil {
		*s = nil
		return nil
	}
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("stringSliceJSON: unsupported type %T", value)
	}
	if len(data) == 0 {
		*s = nil
		return nil
	}
	return json.Unmarshal(data, (*[]string)(s))
}

type servicesJSON []TunnelAgentService

func (s servicesJSON) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal([]TunnelAgentService(s))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *servicesJSON) Scan(value any) error {
	if value == nil {
		*s = nil
		return nil
	}
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("servicesJSON: unsupported type %T", value)
	}
	if len(data) == 0 {
		*s = nil
		return nil
	}
	return json.Unmarshal(data, (*[]TunnelAgentService)(s))
}

type edgeNodeModel struct {
	ID                  string `gorm:"primaryKey;size:191"`
	GroupID             string `gorm:"not null;index"`
	Category            string `gorm:"not null"`
	Kind                string `gorm:"not null"`
	Name                string
	Hostname            string
	Addresses           stringSliceJSON `gorm:"type:jsonb;default:'[]'"`
	Version             string
	AgentVersion        string
	AgentDesiredVersion string
	LastUpgradeAt       *time.Time
	NodeKeyHash         string
	NodeKeyVersion      int
	LastSeen            *time.Time
	CreatedAt           time.Time `gorm:"not null"`
	UpdatedAt           time.Time `gorm:"not null"`
}

func (edgeNodeModel) TableName() string { return "edge_nodes" }

func (m edgeNodeModel) toEntity() EdgeNode {
	node := EdgeNode{
		ID:                  m.ID,
		GroupID:             m.GroupID,
		Category:            NodeCategory(m.Category),
		Kind:                m.Kind,
		Name:                m.Name,
		Hostname:            m.Hostname,
		Addresses:           []string(m.Addresses),
		Version:             m.Version,
		AgentVersion:        m.AgentVersion,
		AgentDesiredVersion: m.AgentDesiredVersion,
		NodeKeyHash:         m.NodeKeyHash,
		NodeKeyVersion:      m.NodeKeyVersion,
		CreatedAt:           m.CreatedAt.UTC(),
		UpdatedAt:           m.UpdatedAt.UTC(),
	}
	if m.LastUpgradeAt != nil {
		node.LastUpgradeAt = m.LastUpgradeAt.UTC()
	}
	if m.LastSeen != nil {
		node.LastSeen = m.LastSeen.UTC()
	}
	return node
}

func edgeNodeModelFromEntity(node EdgeNode) edgeNodeModel {
	model := edgeNodeModel{
		ID:                  node.ID,
		GroupID:             node.GroupID,
		Category:            string(node.Category),
		Kind:                node.Kind,
		Name:                node.Name,
		Hostname:            node.Hostname,
		Addresses:           stringSliceJSON(node.Addresses),
		Version:             node.Version,
		AgentVersion:        node.AgentVersion,
		AgentDesiredVersion: node.AgentDesiredVersion,
		NodeKeyHash:         node.NodeKeyHash,
		NodeKeyVersion:      node.NodeKeyVersion,
		CreatedAt:           node.CreatedAt.UTC(),
		UpdatedAt:           node.UpdatedAt.UTC(),
	}
	if !node.LastUpgradeAt.IsZero() {
		upgraded := node.LastUpgradeAt.UTC()
		model.LastUpgradeAt = &upgraded
	}
	if !node.LastSeen.IsZero() {
		seen := node.LastSeen.UTC()
		model.LastSeen = &seen
	}
	return model
}

type tunnelGroupModel struct {
	ID             string `gorm:"primaryKey;size:191"`
	Name           string `gorm:"not null"`
	Description    string
	ListenAddress  string          `gorm:"not null"`
	EdgeNodeIDs    stringSliceJSON `gorm:"type:jsonb;default:'[]'"`
	Transports     stringSliceJSON `gorm:"type:jsonb;default:'[]'"`
	EnableCompress bool            `gorm:"not null;default:false"`
	CreatedAt      time.Time       `gorm:"not null"`
	UpdatedAt      time.Time       `gorm:"not null"`
}

func (tunnelGroupModel) TableName() string { return "tunnel_groups" }

func (m tunnelGroupModel) toEntity() TunnelGroup {
	return TunnelGroup{
		ID:             m.ID,
		Name:           m.Name,
		Description:    m.Description,
		ListenAddress:  m.ListenAddress,
		EdgeNodeIDs:    []string(m.EdgeNodeIDs),
		Transports:     []string(m.Transports),
		EnableCompress: m.EnableCompress,
		CreatedAt:      m.CreatedAt.UTC(),
		UpdatedAt:      m.UpdatedAt.UTC(),
	}
}

func tunnelGroupModelFromEntity(group TunnelGroup) tunnelGroupModel {
	return tunnelGroupModel{
		ID:             group.ID,
		Name:           group.Name,
		Description:    group.Description,
		ListenAddress:  group.ListenAddress,
		EdgeNodeIDs:    stringSliceJSON(group.EdgeNodeIDs),
		Transports:     stringSliceJSON(group.Transports),
		EnableCompress: group.EnableCompress,
		CreatedAt:      group.CreatedAt.UTC(),
		UpdatedAt:      group.UpdatedAt.UTC(),
	}
}

type tunnelAgentModel struct {
	ID          string `gorm:"primaryKey;size:191"`
	NodeID      string `gorm:"not null;index"`
	GroupID     string `gorm:"not null;index"`
	Description string
	KeyHash     string       `gorm:"not null"`
	KeyVersion  int          `gorm:"not null"`
	Enabled     bool         `gorm:"not null;default:true"`
	Services    servicesJSON `gorm:"type:jsonb;default:'[]'"`
	CreatedAt   time.Time    `gorm:"not null"`
	UpdatedAt   time.Time    `gorm:"not null"`
}

func (tunnelAgentModel) TableName() string { return "tunnel_agents" }

func (m tunnelAgentModel) toEntity() TunnelAgent {
	return TunnelAgent{
		ID:          m.ID,
		NodeID:      m.NodeID,
		GroupID:     m.GroupID,
		Description: m.Description,
		KeyHash:     m.KeyHash,
		KeyVersion:  m.KeyVersion,
		Enabled:     m.Enabled,
		Services:    []TunnelAgentService(m.Services),
		CreatedAt:   m.CreatedAt.UTC(),
		UpdatedAt:   m.UpdatedAt.UTC(),
	}
}

func tunnelAgentModelFromEntity(agent TunnelAgent) tunnelAgentModel {
	return tunnelAgentModel{
		ID:          agent.ID,
		NodeID:      agent.NodeID,
		GroupID:     agent.GroupID,
		Description: agent.Description,
		KeyHash:     agent.KeyHash,
		KeyVersion:  agent.KeyVersion,
		Enabled:     agent.Enabled,
		Services:    servicesJSON(agent.Services),
		CreatedAt:   agent.CreatedAt.UTC(),
		UpdatedAt:   agent.UpdatedAt.UTC(),
	}
}
