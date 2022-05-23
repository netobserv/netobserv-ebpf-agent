//go:build e2e

package basic

import (
	"context"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster"
	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster/tester"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

const (
	clusterNamePrefix = "basic-test-cluster"
	testTimeout       = 120 * time.Second
)

var (
	testCluster *cluster.Kind
)

func TestMain(m *testing.M) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	testCluster = cluster.NewKind(envconf.RandomName(clusterNamePrefix, 24), path.Join("..", ".."),
		cluster.AddDeployments(cluster.Deployment{ManifestFile: "manifests/pods.yml"}))
	testCluster.Run(m)
}

// TestBasicFlowCapture checks that the agent is correctly capturing the request/response flows
// between the pods/service deployed from the manifests/pods.yml file
func TestBasicFlowCapture(t *testing.T) {
	var clientIP, serverServiceIP, serverPodIP string
	f1 := features.New("basic flow capture").Setup(
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			clientIP, serverServiceIP, serverPodIP = fetchSourceAndDestinationAddresses(ctx, t, cfg)
			logrus.WithFields(logrus.Fields{
				"clientIP":        clientIP,
				"serverServiceIP": serverServiceIP,
				"serverPodIP":     serverPodIP,
			}).Debug("fetched podIPs")
			return ctx
		},
	).Assess("correctness of client -> server (as Service) request flows",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			return checkFlow(ctx, t,
				`{DstK8S_OwnerName="server",SrcK8S_OwnerName="client"}|="\"DstAddr\":\"`+
					serverServiceIP+`\""`,
				clientIP, serverServiceIP, "DstPort")
		},
	).Assess("correctness of client -> server (as Pod) request flows",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			return checkFlow(ctx, t,
				`{DstK8S_OwnerName="server",SrcK8S_OwnerName="client"}|="\"DstAddr\":\"`+
					serverPodIP+`\""`,
				clientIP, serverPodIP, "DstPort")
		},
	).Assess("correctness of server (from Service) -> client response flows",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			return checkFlow(ctx, t,
				`{DstK8S_OwnerName="client",SrcK8S_OwnerName="server"}|="\"SrcAddr\":\"`+
					serverServiceIP+`\""`,
				serverServiceIP, clientIP, "SrcPort")
		},
	).Assess("correctness of server (from Pod) -> client response flows",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			return checkFlow(ctx, t,
				`{DstK8S_OwnerName="client",SrcK8S_OwnerName="server"}|="\"SrcAddr\":\"`+
					serverPodIP+`\""`,
				serverPodIP, clientIP, "SrcPort")
		},
	).Feature()
	testCluster.TestEnv().Test(t, f1)
}

// TODO: find a way to extract the Pods' MAC
func fetchSourceAndDestinationAddresses(
	ctx context.Context, t *testing.T, cfg *envconf.Config,
) (clientIP, serverServiceIP, serverPodIP string) {
	kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	require.NoError(t, err)
	// extract source Pod information from kubernetes
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		client, err := kclient.CoreV1().Pods("default").
			Get(ctx, "client", metav1.GetOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, client.Status.PodIP)
		clientIP = client.Status.PodIP
	}, test.Interval(time.Second))
	// extract destination pod information from kubernetes
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		server, err := kclient.CoreV1().Pods("default").
			List(ctx, metav1.ListOptions{LabelSelector: "app=server"})
		require.NoError(t, err)
		require.Len(t, server.Items, 1)
		require.NotEmpty(t, server.Items)
		require.NotEmpty(t, server.Items[0].Status.PodIP)
		serverPodIP = server.Items[0].Status.PodIP
	}, test.Interval(time.Second))
	// extract destination service information from kubernetes
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		server, err := kclient.CoreV1().Services("default").
			Get(ctx, "server", metav1.GetOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, server.Spec.ClusterIP)
		serverServiceIP = server.Spec.ClusterIP
	}, test.Interval(time.Second))
	return
}

// checkFlow checks the correctness of flows between HTTP server and client given the expected src &
// dst IPs, and the field where the service port 80 should be placed ("DstPort" for requests,
// "SrcPort" for responses)
func checkFlow(ctx context.Context, t *testing.T, logQL string,
	expectedSrcIP, expectedDstIP, port80ExpectedField string) context.Context {
	var query *tester.LokiQueryResponse
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		query, err = testCluster.Loki().
			Query(1, logQL)
		require.NoError(t, err)
		require.NotNil(t, query)
		require.NotEmpty(t, query.Data.Result)
	}, test.Interval(time.Second))
	require.NotEmpty(t, query.Data.Result)
	result := query.Data.Result[0]
	require.NotEmpty(t, result.Values)
	flow, err := result.Values[0].FlowData()
	require.NoError(t, err)

	assert.Equal(t, expectedSrcIP, flow["SrcAddr"])
	assert.Equal(t, expectedDstIP, flow["DstAddr"])
	assert.EqualValues(t, 80, flow[port80ExpectedField])

	assert.EqualValues(t, 2048, flow["Etype"])
	assert.EqualValues(t, 6, flow["Proto"])

	// TODO: verify that they actually contain reasonable values
	assert.NotEmpty(t, result.Stream["FlowDirection"])
	assert.NotZero(t, flow["Bytes"])
	assert.NotEmpty(t, flow["DstMac"])
	assert.NotZero(t, flow["DstPort"])
	assert.NotEmpty(t, flow["Interface"])
	assert.NotZero(t, flow["Packets"])
	assert.NotEmpty(t, flow["SrcMac"])
	assert.NotZero(t, flow["SrcPort"])
	assert.NotZero(t, flow["TimeFlowEndMs"])
	assert.NotZero(t, flow["TimeFlowStartMs"])
	return ctx
}
