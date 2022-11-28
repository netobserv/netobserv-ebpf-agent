//go:build e2e

package basic

import (
	"path"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/e2e/basic"
	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster"
	"github.com/sirupsen/logrus"
)

const (
	clusterNamePrefix = "ipfix-test-cluster"
	testTimeout       = 20 * time.Minute
	namespace         = "default"
)

var (
	testCluster *cluster.Kind
)

func TestMain(m *testing.M) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)

	testCluster = cluster.NewKind(
		clusterNamePrefix+time.Now().Format("20060102-150405"),
		path.Join("..", ".."),
		cluster.Timeout(testTimeout),
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
