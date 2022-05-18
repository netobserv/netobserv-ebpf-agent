package basic

import (
	"context"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/test/cluster"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

const (
	clusterNamePrefix = "test-cluster"
)

var (
	kind *cluster.Kind
)

func TestMain(m *testing.M) {
	logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	kind = cluster.NewKind(envconf.RandomName(clusterNamePrefix, 16))
	kind.Run(m)
}

func TestTest(t *testing.T) {
	f1 := features.New("count pod").
		WithLabel("type", "pod-count").
		Assess("pods from kube-system", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var pods v1.PodList
			err := cfg.Client().Resources("default").List(context.TODO(), &pods)
			if err != nil {
				t.Fatal(err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("no pods in namespace kube-system")
			}
			return ctx
		}).Feature()
	kind.TestEnv().Test(t, f1)
}
