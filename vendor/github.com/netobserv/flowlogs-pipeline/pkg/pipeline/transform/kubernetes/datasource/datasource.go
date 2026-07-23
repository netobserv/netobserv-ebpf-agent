package datasource

import (
	"github.com/netobserv/flowlogs-pipeline/pkg/operational"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/kubernetes/informers"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/kubernetes/model"
)

type Datasource struct {
	// Informers provides local Kubernetes informers (may be nil when k8scache is enabled).
	Informers informers.Interface
	// kubernetesStore, when set, is used for IndexLookup and GetNodeByName instead of Informers.
	// It is populated by the k8s cache sync gRPC server when receiving updates from flp-informers.
	// When k8scache is enabled, Informers is nil and only kubernetesStore is used.
	// This is set once during initialization before any concurrent access begins.
	kubernetesStore *KubernetesStore
}

// SetKubernetesStore sets the Kubernetes store (used when k8s cache server is enabled).
// This must be called during initialization, before the pipeline starts processing flows.
func (d *Datasource) SetKubernetesStore(store *KubernetesStore) {
	d.kubernetesStore = store
}

func NewInformerDatasource(kubeconfig string, infConfig *informers.Config, opMetrics *operational.Metrics) (*Datasource, error) {
	inf := &informers.Informers{}
	if err := inf.InitFromConfig(kubeconfig, infConfig, opMetrics); err != nil {
		return nil, err
	}
	return &Datasource{Informers: inf}, nil
}

// NewDatasourceK8sCache creates a datasource for k8scache mode without local informers.
// In this mode, the KubernetesStore will be set later by the k8scache gRPC server,
// and all lookups will use the centralized cache (Informers is nil to save resources).
func NewDatasourceK8sCache() *Datasource {
	return &Datasource{
		Informers: nil, // No local informers when using k8scache
	}
}

func (d *Datasource) IndexLookup(potentialKeys []string, ip string) *model.ResourceMetaData {
	if d.kubernetesStore != nil {
		return d.kubernetesStore.IndexLookup(potentialKeys, ip)
	}
	// Fallback to local informers if available (nil when k8scache is enabled)
	if d.Informers != nil {
		return d.Informers.IndexLookup(potentialKeys, ip)
	}
	return nil
}

func (d *Datasource) GetNodeByName(name string) (*model.ResourceMetaData, error) {
	if d.kubernetesStore != nil {
		return d.kubernetesStore.GetNodeByName(name)
	}
	// Fallback to local informers if available (nil when k8scache is enabled)
	if d.Informers != nil {
		return d.Informers.GetNodeByName(name)
	}
	return nil, nil
}

// ApplyCacheAddOrUpdate adds or updates the given entries in the Kubernetes store.
func (d *Datasource) ApplyCacheAddOrUpdate(entries []*model.ResourceMetaData) {
	if d.kubernetesStore != nil {
		d.kubernetesStore.AddOrUpdate(entries)
	}
}

// ApplyCacheDelete removes the given entries from the Kubernetes store.
func (d *Datasource) ApplyCacheDelete(entries []*model.ResourceMetaData) {
	if d.kubernetesStore != nil {
		d.kubernetesStore.Delete(entries)
	}
}

// ApplyCacheReplace replaces the entire Kubernetes store with the given entries (full snapshot).
func (d *Datasource) ApplyCacheReplace(entries []*model.ResourceMetaData) {
	if d.kubernetesStore != nil {
		d.kubernetesStore.Replace(entries)
	}
}
