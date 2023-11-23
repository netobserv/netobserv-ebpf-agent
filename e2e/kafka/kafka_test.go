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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
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
	scheme.Scheme.AddKnownTypeWithName(schema.GroupVersionKind{
		Group:   "kafka.strimzi.io",
		Version: "v1beta2",
		Kind:    "Kafka",
	}, &Kafka{})

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
				client, err := cfg.NewClient()
				if err != nil {
					return fmt.Errorf("can't create k8s client: %w", err)
				}
				// wait for kafka to be ready
				kfk := Kafka{ObjectMeta: metav1.ObjectMeta{
					Namespace: namespace, Name: "kafka-cluster",
				}}
				var depl appsv1.DeploymentList
				err = cfg.Client().Resources(namespace).List(context.TODO(), &depl)
				if err != nil {
					return fmt.Errorf("can't list depls: %w", err)
				}
				deplInfo := []string{}
				for _, p := range depl.Items {
					deplInfo = append(deplInfo, fmt.Sprintf("%s (%d/%d)", p.Name, p.Status.ReadyReplicas, p.Status.Replicas))
				}
				klog.Infof("Deployments: " + strings.Join(deplInfo, " ,,,,, "))
				var sfs appsv1.StatefulSetList
				err = cfg.Client().Resources(namespace).List(context.TODO(), &sfs)
				if err != nil {
					return fmt.Errorf("can't list sfs: %w", err)
				}
				sfsInfo := []string{}
				for _, p := range sfs.Items {
					sfsInfo = append(sfsInfo, fmt.Sprintf("%s (%d/%d/%d)", p.Name, p.Status.ReadyReplicas, p.Status.AvailableReplicas, p.Status.Replicas))
				}
				klog.Infof("StatefulSets: " + strings.Join(sfsInfo, " ,,,,, "))
				if err := wait.For(conditions.New(client.Resources()).
					ResourceMatch(&kfk, func(object k8s.Object) bool {
						kafka, ok := object.(*Kafka)
						if !ok {
							klog.Errorf("could not cast Kafka obj: %v", object)
							return false
						}
						for _, cond := range kafka.Status.Conditions {
							klog.WithFields(logrus.Fields{
								"reason": cond.Reason,
								"msg":    cond.Message,
								"type":   cond.Type,
								"status": cond.Status,
							}).Info("Waiting for kafka to be up and running")
							if cond.Type == conditionReady {
								return cond.Status == metav1.ConditionTrue
							}
						}
						return kafka.Status.Ready()
					}), wait.WithTimeout(time.Minute*1)); err != nil {
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

const conditionReady = "Ready"

// Kafka meta object for its usage within the API
type Kafka struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            *KafkaStatus `json:"status,omitempty"`
}

type KafkaStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

func (k *Kafka) DeepCopyObject() runtime.Object {
	return &(*k)
}

func (ks *KafkaStatus) Ready() bool {
	if ks == nil {
		return false
	}
	klog.Infof("Kafka len of conditions: %d", len(ks.Conditions))
	for _, cond := range ks.Conditions {
		klog.WithFields(logrus.Fields{
			"reason": cond.Reason,
			"msg":    cond.Message,
			"type":   cond.Type,
			"status": cond.Status,
		}).Info("Waiting for kafka to be up and running")
		if cond.Type == conditionReady {
			return cond.Status == metav1.ConditionTrue
		}
	}
	return false
}
