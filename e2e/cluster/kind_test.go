package cluster

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrderManifests(t *testing.T) {
	tc := NewKind("foo", ".",
		Deploy("traffic-gen", Deployment{ManifestFile: "pods.yml"}),
		Deploy("sql", Deployment{Order: ExternalServices, ManifestFile: "sql"}),
		Deploy(LokiID, Deployment{Order: ExternalServices, ManifestFile: "loki"}))

	// verify that deployments are overridden and/or inserted in proper order
	require.Equal(t, []Deployment{
		{Order: Preconditions, ManifestFile: path.Join(packageDir(), "base", "01-permissions.yml")},
		{Order: ExternalServices, ManifestFile: "loki"},
		{Order: ExternalServices, ManifestFile: "sql"},
		{Order: NetObservServices, ManifestFile: path.Join(packageDir(), "base", "03-flp.yml")},
		{Order: Agent, ManifestFile: path.Join(packageDir(), "base", "04-agent.yml")},
		{ManifestFile: "pods.yml"},
	}, tc.orderedManifests())
}
