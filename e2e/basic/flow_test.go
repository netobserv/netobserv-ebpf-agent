//go:build e2e

package basic

import (
	"path"
	"testing"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster"
	"github.com/sirupsen/logrus"
)

const (
	clusterNamePrefix = "basic-test-cluster"
	testTimeout       = 120 * time.Second
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
		cluster.Deploy(cluster.Deployment{
			Order: cluster.AfterAgent, ManifestFile: "manifests/pods.yml"}),
	)
	testCluster.Run(m)
}

// TestBasicFlowCapture checks that the agent is correctly capturing the request/response flows
// between the pods/service deployed from the manifests/pods.yml file
func TestBasicFlowCapture(t *testing.T) {
	bt := FlowCaptureTester{
		Cluster:   testCluster,
		Namespace: namespace,
		Timeout:   testTimeout,
	}
	bt.DoTest(t)
}
