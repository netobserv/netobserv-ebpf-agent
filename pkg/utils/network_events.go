package utils

import (
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	ovnmodel "github.com/ovn-org/ovn-kubernetes/go-controller/observability-lib/model"
)

func NetworkEventToMap(netev ovnmodel.NetworkEvent) map[string]string {
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

func NetworkEventsToStrings(flow config.GenericMap) []string {
	if ne, found := flow["NetworkEvents"]; found {
		if neList, isList := ne.([]any); isList {
			var messages []string
			for _, item := range neList {
				if neItem, isMap := item.(map[string]any); isMap {
					messages = append(messages, networkEventItemToString(neItem))
				}
			}
			return messages
		}
	}
	return nil
}

func networkEventItemToString(in map[string]any) string {
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
