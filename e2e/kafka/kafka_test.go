//go:build e2e

package basic

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/e2e/basic"
	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	clusterNamePrefix = "kafka-test-cluster"
	testTimeout       = 10 * time.Minute
	namespace         = "default"
)

var (
	klog        = logrus.WithField("component", "Kafka")
	testCluster *cluster.Kind
)

func TestMain(m *testing.M) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)

	testCluster = cluster.NewKind(
		clusterNamePrefix+time.Now().Format("20060102-150405"),
		path.Join("..", ".."),
		cluster.Timeout(testTimeout),
		cluster.Deploy(cluster.Deployment{
			Order: cluster.Preconditions, ManifestFile: path.Join("manifests", "10-kafka-crd.yml"),
		}),
		cluster.Deploy(cluster.Deployment{
			Order: cluster.ExternalServices, ManifestFile: path.Join("manifests", "11-kafka-cluster.yml"),
			ReadyFunction: func(cfg *envconf.Config) error {
				// wait for kafka to be ready
				if !checkResources(cfg.Client(), "kafka-cluster-zookeeper", "kafka-cluster-kafka", "strimzi-cluster-operator", "kafka-cluster-entity-operator") {
					return errors.New("waiting for kafka cluster to be ready")
				}
				return nil
			},
		}),
		cluster.Override(cluster.FlowLogsPipeline, cluster.Deployment{
			Order: cluster.NetObservServices, ManifestFile: path.Join("manifests", "20-flp-transformer.yml"),
		}),
		cluster.Override(cluster.Agent, cluster.Deployment{
			Order: cluster.WithAgent, ManifestFile: path.Join("manifests", "30-agent.yml"),
		}),
		cluster.Deploy(cluster.Deployment{
			Order:        cluster.AfterAgent,
			ManifestFile: path.Join("..", "basic", "manifests", "pods.yml"),
		}),
	)
	testCluster.Run(m)
}

// TestBasicFlowCapture checks that the agent is correctly capturing the request/response flows
// between the pods/service deployed from the manifests/pods.yml file
func TestBasicFlowCapture(t *testing.T) {
	bt := basic.FlowCaptureTester{
		Cluster:   testCluster,
		Namespace: namespace,
		Timeout:   testTimeout,
	}
	bt.DoTest(t, false)
}

func checkResources(client klient.Client, list ...string) bool {
	ready := map[string]bool{}
	for _, name := range list {
		ready[name] = false
	}
	var depl appsv1.DeploymentList
	err := client.Resources(namespace).List(context.TODO(), &depl)
	if err != nil {
		klog.Errorf("Can't list deployments: %v", err)
		return false
	}
	deplInfo := []string{}
	for _, p := range depl.Items {
		deplInfo = append(deplInfo, fmt.Sprintf("%s (%d/%d)", p.Name, p.Status.ReadyReplicas, p.Status.Replicas))
		if _, toCheck := ready[p.Name]; toCheck {
			ready[p.Name] = p.Status.ReadyReplicas == 1
		}
	}
	klog.Infof("Deployments: " + strings.Join(deplInfo, ", "))
	var sfs appsv1.StatefulSetList
	err = client.Resources(namespace).List(context.TODO(), &sfs)
	if err != nil {
		klog.Errorf("Can't list stateful sets: %v", err)
		return false
	}
	sfsInfo := []string{}
	for _, p := range sfs.Items {
		sfsInfo = append(sfsInfo, fmt.Sprintf("%s (%d/%d/%d)", p.Name, p.Status.ReadyReplicas, p.Status.AvailableReplicas, p.Status.Replicas))
		if _, toCheck := ready[p.Name]; toCheck {
			ready[p.Name] = p.Status.ReadyReplicas == 1
		}
	}
	klog.Infof("StatefulSets: " + strings.Join(sfsInfo, ", "))
	for _, state := range ready {
		if !state {
			return false
		}
	}
	return true
}
