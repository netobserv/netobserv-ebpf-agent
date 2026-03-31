package networkevents

import (
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	ovnmodel "github.com/ovn-org/ovn-kubernetes/go-controller/observability-lib/model"
)

const (
	// Use an arbitrary space to inject network event causes into skbDropReason
	// As long as we just manage kernel (0 to 0<<16) and OVS (3<<16 to +~10), that leaves plenty of room e.g. above 1<<24
	// We may need to revisit if other systems are managed and overlap
	customDropReasonSubSysOVNEvents = (1 << 24)
)

var (
	// TODO: expose constants in ovnk-lib, see https://github.com/ovn-kubernetes/ovn-kubernetes/blob/29c8dfba1e9ababe492bf8809373460b0581df76/go-controller/observability-lib/model/network_event.go#L12-L20
	causes = []string{
		"Unknown",
		"EgressFirewall",
		"AdminNetworkPolicy",
		"BaselineAdminNetworkPolicy",
		"NetworkPolicy",
		"MulticastNS",
		"MulticastCluster",
		"NetpolNode",
		"NetpolNamespace",
		"UDNIsolation",
	}
	mapCauses = map[string]uint32{}
)

func init() {
	for i, cause := range causes {
		mapCauses[cause] = uint32(i)
	}
}

func ToMap(netev ovnmodel.NetworkEvent) map[string]string {
	if acl, ok := netev.(*ovnmodel.ACLEvent); ok {
		return map[string]string{
			"Action":    acl.Action,
			"Type":      acl.Actor,
			"Feature":   "acl",
			"Name":      acl.Name,
			"Namespace": acl.Namespace,
			"Direction": acl.Direction,
		}
	}
	return map[string]string{
		"Message": netev.String(),
	}
}

func MapToStrings(flow config.GenericMap) []string {
	if ne, found := flow["NetworkEvents"]; found {
		// Check for structured nested data
		if neList, ok := ne.([]map[string]string); ok {
			var messages []string
			for _, ne := range neList {
				messages = append(messages, itemToString(ne))
			}
			return messages
		}
		// Check for unstructured nested data
		if neList, isList := ne.([]any); isList {
			var messages []string
			for _, item := range neList {
				if neItem, isMap := item.(map[string]any); isMap {
					messages = append(messages, itemToStringUnstructured(neItem))
				}
			}
			return messages
		}
	}
	return nil
}

func itemToString(in map[string]string) string {
	if msg := in["Message"]; msg != "" {
		return msg
	}
	if feat := in["Feature"]; feat == "acl" {
		aclObj := ovnmodel.ACLEvent{
			Action:    in["Action"],
			Actor:     in["Type"],
			Name:      in["Name"],
			Namespace: in["Namespace"],
			Direction: in["Direction"],
		}
		return aclObj.String()
	}
	return ""
}

func itemToStringUnstructured(in map[string]any) string {
	if msg := getAsString(in, "Message"); msg != "" {
		return msg
	}
	if feat := getAsString(in, "Feature"); feat == "acl" {
		aclObj := ovnmodel.ACLEvent{
			Action:    getAsString(in, "Action"),
			Actor:     getAsString(in, "Type"),
			Name:      getAsString(in, "Name"),
			Namespace: getAsString(in, "Namespace"),
			Direction: getAsString(in, "Direction"),
		}
		return aclObj.String()
	}
	return ""
}

func getAsString(in map[string]any, key string) string {
	if anyV, hasKey := in[key]; hasKey {
		if v, isStr := anyV.(string); isStr {
			return v
		}
	}
	return ""
}

func ToDropReasonCode(netev ovnmodel.NetworkEvent) (uint32, bool) {
	if acl, ok := netev.(*ovnmodel.ACLEvent); ok {
		if acl.Action == "drop" {
			if i, ok := mapCauses[acl.Actor]; ok {
				return customDropReasonSubSysOVNEvents + i, true
			}
			return customDropReasonSubSysOVNEvents + 0, true // stands for "unknown"
		}
	}
	return 0, false
}

func DropReasonCodeToString(cause uint32) string {
	if cause < customDropReasonSubSysOVNEvents || cause-customDropReasonSubSysOVNEvents >= uint32(len(causes)) {
		return ""
	}
	return causes[cause-customDropReasonSubSysOVNEvents]
}
