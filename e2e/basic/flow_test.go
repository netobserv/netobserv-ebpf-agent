//go:build e2e

package basic

import (
	"context"
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
)

var (
	kind *cluster.Kind
)

func TestMain(m *testing.M) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	kind = cluster.NewKind(envconf.RandomName(clusterNamePrefix, 24),
		cluster.AddDeployments(cluster.Deployment{ManifestFile: "manifests/pods.yml"}))
	kind.Run(m)
}

func TestTest(t *testing.T) {
	// TODO: find a way to extract the Pods' MAC
	var serverIP, clientIP string
	f1 := features.New("basic flow capture").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			require.NoError(t, err)
			// extract source Pod information from kubernetes
			test.Eventually(t, 10*time.Second, func(t require.TestingT) {
				client, err := kclient.CoreV1().Pods("default").
					Get(ctx, "client", metav1.GetOptions{})
				require.NoError(t, err)
				require.NotEmpty(t, client.Status.PodIP)
				clientIP = client.Status.PodIP
			})
			// extract destination service information from kubernetes
			test.Eventually(t, 10*time.Second, func(t require.TestingT) {
				server, err := kclient.CoreV1().Services("default").
					Get(ctx, "server", metav1.GetOptions{})
				require.NoError(t, err)
				require.NotEmpty(t, server.Spec.ClusterIP)
				serverIP = server.Spec.ClusterIP
			})
			return ctx
		}).Assess("client -> server request flow",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// TODO: add as cluster property
			lc := tester.Loki{BaseURL: "http://127.0.0.1:30100"}
			var query *tester.LokiQueryResponse
			test.Eventually(t, 20*time.Second, func(t require.TestingT) {
				var err error
				query, err = lc.Query(1, map[string]string{
					"DstK8S_OwnerName": "server",
					"SrcK8S_OwnerName": "client",
				})
				require.NoError(t, err)
				require.NotNil(t, query)
				require.NotEmpty(t, query.Data.Result)
			})
			require.NotEmpty(t, query.Data.Result)
			result := query.Data.Result[0]
			require.NotEmpty(t, result.Values)
			flow, err := result.Values[0].FlowData()
			require.NoError(t, err)
			assert.NotZero(t, result.Stream["FlowDirection"])
			assert.NotZero(t, flow["Bytes"])
			assert.Equal(t, serverIP, flow["DstAddr"])
			assert.NotEmpty(t, flow["DstMac"])
			assert.EqualValues(t, 80, flow["DstPort"])
			assert.EqualValues(t, 2048, flow["Etype"])
			assert.NotEmpty(t, flow["Interface"])
			assert.NotZero(t, flow["Packets"])
			assert.EqualValues(t, 6, flow["Proto"])
			assert.Equal(t, clientIP, flow["SrcAddr"])
			assert.NotEmpty(t, flow["SrcMac"])
			assert.NotZero(t, flow["SrcPort"])
			// TODO: verify that they actually contain reasonable timestamps
			assert.NotZero(t, flow["TimeFlowEndMs"])
			assert.NotZero(t, flow["TimeFlowStartMs"])
			return ctx
		}).Assess("server -> client response flow",
		func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// TODO: add as cluster property
			lc := tester.Loki{BaseURL: "http://127.0.0.1:30100"}
			var query *tester.LokiQueryResponse
			test.Eventually(t, 20*time.Second, func(t require.TestingT) {
				var err error
				query, err = lc.Query(1, map[string]string{
					"DstK8S_OwnerName": "client",
					"SrcK8S_OwnerName": "server",
				})
				require.NoError(t, err)
				require.NotNil(t, query)
				require.NotEmpty(t, query.Data.Result)
			})
			require.NotEmpty(t, query.Data.Result)
			result := query.Data.Result[0]
			require.NotEmpty(t, result.Values)
			flow, err := result.Values[0].FlowData()
			require.NoError(t, err)
			assert.NotZero(t, result.Stream["FlowDirection"])
			assert.NotZero(t, flow["Bytes"])
			assert.Equal(t, clientIP, flow["DstAddr"])
			assert.NotEmpty(t, flow["DstMac"])
			assert.EqualValues(t, 80, flow["SrcPort"])
			assert.EqualValues(t, 2048, flow["Etype"])
			assert.NotEmpty(t, flow["Interface"])
			assert.NotZero(t, flow["Packets"])
			assert.EqualValues(t, 6, flow["Proto"])
			// TODO: fix, as sometimes it gets the pod ip
			assert.Equal(t, serverIP, flow["SrcAddr"])
			assert.NotEmpty(t, flow["SrcMac"])
			assert.NotZero(t, flow["DstPort"])
			// TODO: verify that they actually contain reasonable timestamps
			assert.NotZero(t, flow["TimeFlowEndMs"])
			assert.NotZero(t, flow["TimeFlowStartMs"])
			return ctx
		}).Feature()
	kind.TestEnv().Test(t, f1)
}
