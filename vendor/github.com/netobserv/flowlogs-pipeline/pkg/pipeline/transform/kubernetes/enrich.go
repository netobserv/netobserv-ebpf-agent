package kubernetes

import (
	"fmt"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	inf "github.com/netobserv/flowlogs-pipeline/pkg/pipeline/transform/kubernetes/informers"
	"github.com/sirupsen/logrus"
)

var informers inf.InformersInterface = &inf.Informers{}

// For testing
func MockInformers() {
	informers = inf.NewInformersMock()
}

func InitFromConfig(kubeConfigPath string) error {
	return informers.InitFromConfig(kubeConfigPath)
}

func Enrich(outputEntry config.GenericMap, rule api.NetworkTransformRule) {
	kubeInfo, err := informers.GetInfo(fmt.Sprintf("%s", outputEntry[rule.Input]))
	if err != nil {
		logrus.WithError(err).Tracef("can't find kubernetes info for IP %v", outputEntry[rule.Input])
		return
	}
	if rule.Assignee != "otel" {
		// NETOBSERV-666: avoid putting empty namespaces or Loki aggregation queries will
		// differentiate between empty and nil namespaces.
		if kubeInfo.Namespace != "" {
			outputEntry[rule.Output+"_Namespace"] = kubeInfo.Namespace
		}
		outputEntry[rule.Output+"_Name"] = kubeInfo.Name
		outputEntry[rule.Output+"_Type"] = kubeInfo.Type
		outputEntry[rule.Output+"_OwnerName"] = kubeInfo.Owner.Name
		outputEntry[rule.Output+"_OwnerType"] = kubeInfo.Owner.Type
		if rule.Parameters != "" {
			for labelKey, labelValue := range kubeInfo.Labels {
				outputEntry[rule.Parameters+"_"+labelKey] = labelValue
			}
		}
		if kubeInfo.HostIP != "" {
			outputEntry[rule.Output+"_HostIP"] = kubeInfo.HostIP
			if kubeInfo.HostName != "" {
				outputEntry[rule.Output+"_HostName"] = kubeInfo.HostName
			}
		}
		fillInK8sZone(outputEntry, rule, *kubeInfo, "_Zone")
	} else {
		// NOTE: Some of these fields are taken from opentelemetry specs.
		// See https://opentelemetry.io/docs/specs/semconv/resource/k8s/
		// Other fields (not specified in the specs) are named similarly
		if kubeInfo.Namespace != "" {
			outputEntry[rule.Output+"k8s.namespace.name"] = kubeInfo.Namespace
		}
		switch kubeInfo.Type {
		case inf.TypeNode:
			outputEntry[rule.Output+"k8s.node.name"] = kubeInfo.Name
			outputEntry[rule.Output+"k8s.node.uid"] = kubeInfo.UID
		case inf.TypePod:
			outputEntry[rule.Output+"k8s.pod.name"] = kubeInfo.Name
			outputEntry[rule.Output+"k8s.pod.uid"] = kubeInfo.UID
		case inf.TypeService:
			outputEntry[rule.Output+"k8s.service.name"] = kubeInfo.Name
			outputEntry[rule.Output+"k8s.service.uid"] = kubeInfo.UID
		}
		outputEntry[rule.Output+"k8s.name"] = kubeInfo.Name
		outputEntry[rule.Output+"k8s.type"] = kubeInfo.Type
		outputEntry[rule.Output+"k8s.owner.name"] = kubeInfo.Owner.Name
		outputEntry[rule.Output+"k8s.owner.type"] = kubeInfo.Owner.Type
		if rule.Parameters != "" {
			for labelKey, labelValue := range kubeInfo.Labels {
				outputEntry[rule.Parameters+"."+labelKey] = labelValue
			}
		}
		if kubeInfo.HostIP != "" {
			outputEntry[rule.Output+"k8s.host.ip"] = kubeInfo.HostIP
			if kubeInfo.HostName != "" {
				outputEntry[rule.Output+"k8s.host.name"] = kubeInfo.HostName
			}
		}
		fillInK8sZone(outputEntry, rule, *kubeInfo, "k8s.zone")
	}
}

const nodeZoneLabelName = "topology.kubernetes.io/zone"

func fillInK8sZone(outputEntry config.GenericMap, rule api.NetworkTransformRule, kubeInfo inf.Info, zonePrefix string) {
	if rule.Kubernetes == nil || !rule.Kubernetes.AddZone {
		//Nothing to do
		return
	}
	switch kubeInfo.Type {
	case inf.TypeNode:
		zone, ok := kubeInfo.Labels[nodeZoneLabelName]
		if ok {
			outputEntry[rule.Output+zonePrefix] = zone
		}
		return
	case inf.TypePod:
		nodeInfo, err := informers.GetNodeInfo(kubeInfo.HostName)
		if err != nil {
			logrus.WithError(err).Tracef("can't find nodes info for node %v", kubeInfo.HostName)
			return
		}
		if nodeInfo != nil {
			zone, ok := nodeInfo.Labels[nodeZoneLabelName]
			if ok {
				outputEntry[rule.Output+zonePrefix] = zone
			}
		}
		return

	case inf.TypeService:
		//A service is not assigned to a dedicated zone, skipping
		return
	}
}

func EnrichLayer(outputEntry config.GenericMap, rule api.NetworkTransformRule) {
	if rule.KubernetesInfra == nil {
		logrus.Error("transformation rule: Missing Kubernetes Infra configuration ")
		return
	}
	outputEntry[rule.KubernetesInfra.Output] = "infra"
	for _, input := range rule.KubernetesInfra.Inputs {
		if objectIsApp(fmt.Sprintf("%s", outputEntry[input]), rule.KubernetesInfra.InfraPrefix) {
			outputEntry[rule.KubernetesInfra.Output] = "app"
			return
		}
	}
}

const openshiftNamespacePrefix = "openshift-"
const openshiftPrefixLen = len(openshiftNamespacePrefix)

func objectIsApp(addr string, additionalInfraPrefix string) bool {
	obj, err := informers.GetInfo(addr)
	if err != nil {
		logrus.WithError(err).Tracef("can't find kubernetes info for IP %s", addr)
		return false
	}
	nsLen := len(obj.Namespace)
	additionalPrefixLen := len(additionalInfraPrefix)
	if nsLen == 0 {
		return false
	}
	if nsLen >= openshiftPrefixLen && obj.Namespace[:openshiftPrefixLen] == openshiftNamespacePrefix {
		return false
	}
	if nsLen >= additionalPrefixLen && obj.Namespace[:additionalPrefixLen] == additionalInfraPrefix {
		return false
	}
	//Special case with openshift and kubernetes service in default namespace
	if obj.Namespace == "default" && (obj.Name == "kubernetes" || obj.Name == "openshift") {
		return false
	}
	return true
}
