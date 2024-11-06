package cluster

import (
	"os"
	"path"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestOrderManifests(t *testing.T) {
	if os.Getenv("ACTIONS_RUNNER_DEBUG") == "true" {
		logrus.StandardLogger().SetLevel(logrus.DebugLevel)
	}
	tc := NewKind("foo", ".",
		Deploy(Deployment{ManifestFile: "pods.yml"}),
		Deploy(Deployment{Order: ExternalServices, ManifestFile: "sql"}),
		Override(Loki, Deployment{Order: ExternalServices, ManifestFile: "loki"}))

	var orders []DeployOrder
	var files []string
	for _, m := range tc.orderedManifests() {
		orders = append(orders, m.Order)
		files = append(files, m.ManifestFile)
	}

	// verify that deployments are overridden and/or inserted in proper order
	require.Equal(t, []DeployOrder{
		Preconditions,
		ExternalServices,
		ExternalServices,
		NetObservServices,
		WithAgent,
		0,
	}, orders)
	require.Equal(t, []string{
		path.Join(packageDir(), "base", "01-permissions.yml"),
		"sql",
		"loki",
		path.Join(packageDir(), "base", "03-flp.yml"),
		path.Join(packageDir(), "base", "04-agent.yml"),
		"pods.yml",
	}, files)
}
