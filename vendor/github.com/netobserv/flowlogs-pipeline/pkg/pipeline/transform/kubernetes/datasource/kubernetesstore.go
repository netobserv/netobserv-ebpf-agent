package datasource

import (
	"errors"
	"fmt"
	"sync"

	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/kubernetes/model"
)

func storeKey(meta *model.ResourceMetaData) string {
	return fmt.Sprintf("%s/%s/%s", meta.Kind, meta.Namespace, meta.Name)
}

// KubernetesStore holds Kubernetes resource metadata (pods, nodes, services) used for enrichment.
// It can be populated via the k8s cache sync gRPC stream or left empty when using informers.
// It supports snapshot replace and incremental add/update/delete, and provides the same
// lookup interface (IndexLookup, GetNodeByName) used by enrichment.
type KubernetesStore struct {
	mu sync.RWMutex
	// primary key -> meta (kind/namespace/name)
	byKey map[string]*model.ResourceMetaData
	// index: IP -> meta (first match wins; pods may have multiple IPs)
	byIP map[string]*model.ResourceMetaData
	// index: node name -> meta (for Node kind)
	byNodeName map[string]*model.ResourceMetaData
	// index: secondary network key -> meta (for custom key lookup)
	bySecondaryKey map[string]*model.ResourceMetaData
}

// NewKubernetesStore creates an empty KubernetesStore.
func NewKubernetesStore() *KubernetesStore {
	return &KubernetesStore{
		byKey:          make(map[string]*model.ResourceMetaData),
		byIP:           make(map[string]*model.ResourceMetaData),
		byNodeName:     make(map[string]*model.ResourceMetaData),
		bySecondaryKey: make(map[string]*model.ResourceMetaData),
	}
}

// removeFromIndexes removes all index entries for the given meta (by key).
// Caller must hold mu (write).
// Only removes entries if they belong to this resource (by UID), preserving "first match wins".
func (s *KubernetesStore) removeFromIndexes(meta *model.ResourceMetaData) {
	if meta == nil {
		return
	}
	for _, ip := range meta.IPs {
		// Only delete if the current owner matches (by UID)
		if existing, ok := s.byIP[ip]; ok && existing != nil && existing.UID == meta.UID {
			delete(s.byIP, ip)
		}
	}
	if meta.Kind == model.KindNode && meta.Name != "" {
		// Only delete if the current owner matches (by UID)
		if existing, ok := s.byNodeName[meta.Name]; ok && existing != nil && existing.UID == meta.UID {
			delete(s.byNodeName, meta.Name)
		}
	}
	for _, k := range meta.SecondaryNetKeys {
		// Only delete if the current owner matches (by UID)
		if existing, ok := s.bySecondaryKey[k]; ok && existing != nil && existing.UID == meta.UID {
			delete(s.bySecondaryKey, k)
		}
	}
}

// addToIndexes adds the meta to all index maps.
// Caller must hold mu (write).
// Honors "first match wins" for byIP - does not overwrite existing entries.
func (s *KubernetesStore) addToIndexes(meta *model.ResourceMetaData) {
	if meta == nil {
		return
	}
	for _, ip := range meta.IPs {
		// First match wins - don't overwrite existing entry
		if _, exists := s.byIP[ip]; !exists {
			s.byIP[ip] = meta
		}
	}
	if meta.Kind == model.KindNode && meta.Name != "" {
		s.byNodeName[meta.Name] = meta
	}
	for _, k := range meta.SecondaryNetKeys {
		s.bySecondaryKey[k] = meta
	}
}

// Replace replaces the entire store with the given entries (full snapshot).
// Used when receiving a full snapshot from the k8s cache sync client (is_snapshot=true).
func (s *KubernetesStore) Replace(entries []*model.ResourceMetaData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byKey = make(map[string]*model.ResourceMetaData)
	s.byIP = make(map[string]*model.ResourceMetaData)
	s.byNodeName = make(map[string]*model.ResourceMetaData)
	s.bySecondaryKey = make(map[string]*model.ResourceMetaData)

	for _, meta := range entries {
		if meta == nil {
			continue // Skip nil entries to avoid panic
		}
		key := storeKey(meta)
		s.byKey[key] = meta
		s.addToIndexes(meta)
	}
}

// AddOrUpdate adds or updates the given entries in the store.
func (s *KubernetesStore) AddOrUpdate(entries []*model.ResourceMetaData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, meta := range entries {
		if meta == nil {
			continue // Skip nil entries to avoid panic
		}
		key := storeKey(meta)
		if existing, ok := s.byKey[key]; ok {
			s.removeFromIndexes(existing)
		}
		s.byKey[key] = meta
		s.addToIndexes(meta)
	}
}

// Delete removes the given entries from the store.
// Entries must have at least Kind, Namespace, and Name set for identification.
func (s *KubernetesStore) Delete(entries []*model.ResourceMetaData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, meta := range entries {
		if meta == nil {
			continue // Skip nil entries to avoid panic
		}
		key := storeKey(meta)
		if existing, ok := s.byKey[key]; ok {
			s.removeFromIndexes(existing)
			delete(s.byKey, key)
		}
	}
}

// IndexLookup finds metadata by secondary network keys first, then by IP.
// Implements the same semantics as informers.Interface for use when KubernetesStore is the source.
func (s *KubernetesStore) IndexLookup(potentialKeys []string, ip string) *model.ResourceMetaData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, key := range potentialKeys {
		if meta, ok := s.bySecondaryKey[key]; ok {
			return meta
		}
	}
	if ip != "" {
		if meta, ok := s.byIP[ip]; ok {
			return meta
		}
	}
	return nil
}

// GetNodeByName returns node metadata by name.
func (s *KubernetesStore) GetNodeByName(name string) (*model.ResourceMetaData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if meta, ok := s.byNodeName[name]; ok {
		return meta, nil
	}
	return nil, errors.New("notFound")
}
