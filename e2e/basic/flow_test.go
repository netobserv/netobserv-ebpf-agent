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

// TestSinglePacketFlows uses a known packet size and number to check that,
// (1) packets are aggregated only once,
// (2) once packets are evicted, no more flows are aggregated on top of them.
func TestSinglePacketFlows(t *testing.T) {
	var pingerIP, serverPodIP string
	var latestFlowMS time.Time
	testCluster.TestEnv().Test(t, features.New("single-packet flow capture").Setup(
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			require.NoError(t, err)
			// extract pinger Pod information from kubernetes
			test.Eventually(t, testTimeout, func(t require.TestingT) {
				client, err := kclient.CoreV1().Pods(namespace).
					Get(ctx, "pinger", metav1.GetOptions{})
				require.NoError(t, err)
				require.NotEmpty(t, client.Status.PodIP)
				pingerIP = client.Status.PodIP
			}, test.Interval(time.Second))
			// extract server (ping destination) pod information from kubernetes
			test.Eventually(t, testTimeout, func(t require.TestingT) {
				server, err := kclient.CoreV1().Pods(namespace).
					List(ctx, metav1.ListOptions{LabelSelector: "app=server"})
				require.NoError(t, err)
				require.Len(t, server.Items, 1)
				require.NotEmpty(t, server.Items)
				require.NotEmpty(t, server.Items[0].Status.PodIP)
				serverPodIP = server.Items[0].Status.PodIP
			}, test.Interval(time.Second))
			return ctx
		},
	).Assess("correctness of single, small ICMP packet from pinger to server",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			pods, err := tester.NewPods(cfg)
			require.NoError(t, err)

			logrus.WithField("destinationIP", serverPodIP).Info("Sending ICMP packet")
			stdOut, stdErr, err := pods.Execute(ctx, namespace, "pinger",
				"ping", "-c", "1", serverPodIP)
			require.NoError(t, err)
			logrus.WithFields(logrus.Fields{"stdOut": stdOut, "stdErr": stdErr}).Info("ping sent")

			sent, recv := getPingFlows(t, time.Now().Add(-time.Minute))

			assert.Equal(t, pingerIP, sent["SrcAddr"])
			assert.Equal(t, serverPodIP, sent["DstAddr"])
			assert.EqualValues(t, 98, sent["Bytes"]) // default ping data size + IP+ICMP headers
			assert.EqualValues(t, 1, sent["Packets"])
			assert.Equal(t, pingerIP, recv["DstAddr"])
			assert.Equal(t, serverPodIP, recv["SrcAddr"])
			assert.EqualValues(t, 98, recv["Bytes"]) // default ping data size + IP+ICMP headers
			assert.EqualValues(t, 1, recv["Packets"])

			latestFlowMS = asTime(recv["TimeFlowEndMs"])

			return ctx
		},
	).Assess("correctness of another ICMP packet contained in another flow",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			pods, err := tester.NewPods(cfg)
			require.NoError(t, err)

			logrus.WithField("destinationIP", serverPodIP).Info("Sending ICMP packet")
			stdOut, stdErr, err := pods.Execute(ctx, namespace, "pinger",
				"ping", "-s", "100", "-c", "1", serverPodIP)
			require.NoError(t, err)
			logrus.WithFields(logrus.Fields{"stdOut": stdOut, "stdErr": stdErr}).Info("ping sent")

			// We filter by time to avoid getting twice the same flows
			sent, recv := getPingFlows(t, latestFlowMS)

			assert.Equal(t, pingerIP, sent["SrcAddr"])
			assert.Equal(t, serverPodIP, sent["DstAddr"])
			assert.EqualValues(t, 142, sent["Bytes"]) // 100-byte data size + IP+ICMP headers
			assert.EqualValues(t, 1, sent["Packets"])
			assert.Equal(t, pingerIP, recv["DstAddr"])
			assert.Equal(t, serverPodIP, recv["SrcAddr"])
			assert.EqualValues(t, 142, recv["Bytes"]) // 100-byte data size + IP+ICMP headers
			assert.EqualValues(t, 1, recv["Packets"])
			return ctx
		},
	).Feature())
}

func getPingFlows(t *testing.T, newerThan time.Time) (sent, recv map[string]interface{}) {
	logrus.Info("Verifying that the request/return ICMP packets have been captured individually")
	var query *tester.LokiQueryResponse
	var err error
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query, err = testCluster.Loki().
			Query(1, `{SrcK8S_OwnerName="pinger",DstK8S_OwnerName="server"}|="\"Proto\":1,"`) // Proto 1 == ICMP
		require.NoError(t, err)
		require.NotNil(t, query)
		require.Len(t, query.Data.Result, 1)
		if len(query.Data.Result) > 0 {
			sent, err = query.Data.Result[0].Values[0].FlowData()
			require.NoError(t, err)
			require.LessOrEqual(t, newerThan.UnixMilli(),
				asTime(sent["TimeFlowStartMs"]).UnixMilli())
		}
	}, test.Interval(time.Second))

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query, err = testCluster.Loki().
			Query(1, `{DstK8S_OwnerName="pinger",SrcK8S_OwnerName="server"}|="\"Proto\":1,"`) // Proto 1 == ICMP
		require.NoError(t, err)
		require.NotNil(t, query)
		require.Len(t, query.Data.Result, 1)
		if len(query.Data.Result) > 0 {
			recv, err = query.Data.Result[0].Values[0].FlowData()
			require.NoError(t, err)
			require.LessOrEqual(t, newerThan.UnixMilli(),
				asTime(sent["TimeFlowStartMs"]).UnixMilli())
		}
	}, test.Interval(time.Second))
	return sent, recv
}
