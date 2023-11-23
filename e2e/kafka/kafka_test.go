//go:build e2e

package basic

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/e2e/basic"
	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
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
	// scheme.Scheme.AddKnownTypeWithName(schema.GroupVersionKind{
	// 	Group:   "kafka.strimzi.io",
	// 	Version: "v1beta2",
	// 	Kind:    "Kafka",
	// }, &Kafka{})

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
				if err := waitForKafka(cfg.Client()); err != nil {
					debugListResources(cfg.Client())
					return fmt.Errorf("waiting for kafka cluster to be ready: %w", err)
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
	bt.DoTest(t)
}

func waitForKafka(client klient.Client) error {
	if err := waitForStatefulSet(client, "kafka-cluster-zookeeper"); err != nil {
		return err
	}
	if err := waitForStatefulSet(client, "kafka-cluster-kafka"); err != nil {
		return err
	}
	if err := waitForDeployment(client, "strimzi-cluster-operator"); err != nil {
		return err
	}
	if err := waitForDeployment(client, "kafka-cluster-entity-operator"); err != nil {
		return err
	}
	return nil
}

func waitForDeployment(client klient.Client, name string) error {
	depl := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := wait.For(conditions.New(client.Resources(namespace)).ResourceMatch(&depl, func(object k8s.Object) bool {
		d := object.(*appsv1.Deployment)
		return d.Status.ReadyReplicas == 1
	}), wait.WithTimeout(time.Second*5)); err != nil {
		return fmt.Errorf("deployment %s not ready: %w", name, err)
	}
	return nil
}

func waitForStatefulSet(client klient.Client, name string) error {
	sfs := appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	if err := wait.For(conditions.New(client.Resources(namespace)).ResourceMatch(&sfs, func(object k8s.Object) bool {
		klog.Infof("got obj: %v", object)
		s, ok := object.(*appsv1.StatefulSet)
		if !ok {
			klog.Errorf("could not cast %v", object)
		}
		klog.Infof("Status: %v", s.Status)
		return s.Status.AvailableReplicas == 1 && s.Status.ReadyReplicas == 1
	}), wait.WithTimeout(time.Second*5)); err != nil {
		klog.Errorf("statefulset %s not ready: %v, trying 2", name, err)
		sfs = appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
		if err := wait.For(conditions.New(client.Resources()).ResourceMatch(&sfs, func(object k8s.Object) bool {
			klog.Infof("2: got obj: %v", object)
			s, ok := object.(*appsv1.StatefulSet)
			if !ok {
				klog.Errorf("2: could not cast %v", object)
			}
			klog.Infof("2: Status: %v", s.Status)
			return s.Status.AvailableReplicas == 1 && s.Status.ReadyReplicas == 1
		}), wait.WithTimeout(time.Second*5)); err != nil {
			klog.Errorf("statefulset %s not ready: %v, trying 3", name, err)
			sfs = appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: name}}
			if err := wait.For(conditions.New(client.Resources()).ResourceMatch(&sfs, func(object k8s.Object) bool {
				klog.Infof("3: got obj: %v", object)
				s, ok := object.(*appsv1.StatefulSet)
				if !ok {
					klog.Errorf("3: could not cast %v", object)
				}
				klog.Infof("3: Status: %v", s.Status)
				return s.Status.AvailableReplicas == 1 && s.Status.ReadyReplicas == 1
			}), wait.WithTimeout(time.Second*5)); err != nil {
				return fmt.Errorf("3: statefulset %s not ready: %w", name, err)
			}
		}
	}
	return nil
}

func debugListResources(client klient.Client) {
	var depl appsv1.DeploymentList
	err := client.Resources(namespace).List(context.TODO(), &depl)
	if err != nil {
		klog.Errorf("Can't list deployments: %v", err)
		return
	}
	deplInfo := []string{}
	for _, p := range depl.Items {
		deplInfo = append(deplInfo, fmt.Sprintf("%s (%d/%d)", p.Name, p.Status.ReadyReplicas, p.Status.Replicas))
	}
	klog.Infof("Deployments: " + strings.Join(deplInfo, ", "))
	var sfs appsv1.StatefulSetList
	err = client.Resources(namespace).List(context.TODO(), &sfs)
	if err != nil {
		klog.Errorf("Can't list stateful sets: %v", err)
		return
	}
	sfsInfo := []string{}
	for _, p := range sfs.Items {
		sfsInfo = append(sfsInfo, fmt.Sprintf("%s (%d/%d/%d)", p.Name, p.Status.ReadyReplicas, p.Status.AvailableReplicas, p.Status.Replicas))
	}
	klog.Infof("StatefulSets: " + strings.Join(sfsInfo, ", "))
}
