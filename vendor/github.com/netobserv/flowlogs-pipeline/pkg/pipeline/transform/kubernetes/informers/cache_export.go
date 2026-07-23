package informers

// AddEventHandler adds event handlers to informers for pushing incremental updates.
// Only Pods, Nodes, and Services receive handlers because they contain the full resource
// metadata (IPs, labels, etc.) needed by FLP processors.
//
// ReplicaSets and Deployments are intentionally excluded - they are metadata-only informers
// used solely for ownership resolution (checkParent) via passive lookups (GetByKey).
// They don't need event handlers since we never push their updates to processors.
func (k *Informers) AddEventHandler(handler EventHandler) error {
	if k.pods != nil {
		if _, err := k.pods.AddEventHandler(handler); err != nil {
			return err
		}
	}
	if k.nodes != nil {
		if _, err := k.nodes.AddEventHandler(handler); err != nil {
			return err
		}
	}
	if k.services != nil {
		if _, err := k.services.AddEventHandler(handler); err != nil {
			return err
		}
	}
	return nil
}

// EventHandler defines callbacks for resource changes
// Compatible with cache.ResourceEventHandler interface
type EventHandler interface {
	OnAdd(obj interface{}, isInInitialList bool)
	OnUpdate(oldObj, newObj interface{})
	OnDelete(obj interface{})
}
