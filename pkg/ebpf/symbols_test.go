package ebpf

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlowObjectHasNoPacketPrograms(t *testing.T) {
	spec, err := flows.LoadFlowsBpf()
	require.NoError(t, err)
	for name := range spec.Programs {
		assert.NotContains(t, name, "packet_parse", "flow BPF object must not contain packet programs")
		assert.NotContains(t, name, "pca_parse", "flow BPF object must not contain legacy PCA programs")
	}
}

func TestPacketObjectHasNoFlowPrograms(t *testing.T) {
	spec, err := packets.LoadPacketsBpf()
	require.NoError(t, err)
	for name := range spec.Programs {
		assert.NotContains(t, name, "flow_parse", "packet BPF object must not contain flow programs")
	}
	for name := range spec.Maps {
		lower := strings.ToLower(name)
		assert.NotContains(t, lower, "aggregated_flows", "packet BPF object must not contain flow maps")
	}
}

func TestFlowMapNamesMatchBPF2GoSpec(t *testing.T) {
	spec, err := flows.LoadFlowsBpf()
	require.NoError(t, err)

	tagNames := mapNamesFromEBPFTags(reflect.TypeOf(flows.FlowsBpfMapSpecs{}))
	specNames := bpfDataMapNames(spec.Maps)

	assert.Equal(t, tagNames, specNames,
		"flow bpf2go map spec tags must match embedded BPF object map names")
}

func TestPacketMapNamesMatchBPF2GoSpec(t *testing.T) {
	spec, err := packets.LoadPacketsBpf()
	require.NoError(t, err)

	tagNames := mapNamesFromEBPFTags(reflect.TypeOf(packets.PacketsBpfMapSpecs{}))
	specNames := bpfDataMapNames(spec.Maps)

	assert.Equal(t, tagNames, specNames,
		"packet bpf2go map spec tags must match embedded BPF object map names")
}

func TestFlowMapNameConstantsMatchBPF2GoSpec(t *testing.T) {
	spec, err := flows.LoadFlowsBpf()
	require.NoError(t, err)

	constants := []string{
		flows.FlowsBpfMapAdditionalFlowMetrics,
		flows.FlowsBpfMapAggregatedFlows,
		flows.FlowsBpfMapAggregatedFlowsDns,
		flows.FlowsBpfMapAggregatedFlowsNetworkEvents,
		flows.FlowsBpfMapAggregatedFlowsPktDrop,
		flows.FlowsBpfMapAggregatedFlowsXlat,
		flows.FlowsBpfMapDirectFlows,
		flows.FlowsBpfMapDnsFlows,
		flows.FlowsBpfMapDnsNameMap,
		flows.FlowsBpfMapFilterMap,
		flows.FlowsBpfMapGlobalCounters,
		flows.FlowsBpfMapIpsecEgressMap,
		flows.FlowsBpfMapIpsecIngressMap,
		flows.FlowsBpfMapPeerFilterMap,
		flows.FlowsBpfMapQuicFlows,
	}
	sort.Strings(constants)

	tagNames := mapNamesFromEBPFTags(reflect.TypeOf(flows.FlowsBpfMapSpecs{}))
	assert.Equal(t, tagNames, constants,
		"flow bpf2go BpfMap* constants must match BpfMapSpecs ebpf tags")

	for _, name := range constants {
		assert.Contains(t, spec.Maps, name, "flow BPF object must define map %q", name)
	}
}

func TestPacketMapNameConstantsMatchBPF2GoSpec(t *testing.T) {
	spec, err := packets.LoadPacketsBpf()
	require.NoError(t, err)

	constants := []string{
		packets.PacketsBpfMapFilterMap,
		packets.PacketsBpfMapGlobalCounters,
		packets.PacketsBpfMapPacketRecord,
		packets.PacketsBpfMapPeerFilterMap,
		packets.PacketsBpfMapSslDataEventMap,
		packets.PacketsBpfMapSslFdMap,
		packets.PacketsBpfMapSslFdPendingMap,
		packets.PacketsBpfMapSslReadActiveMap,
	}
	sort.Strings(constants)

	tagNames := mapNamesFromEBPFTags(reflect.TypeOf(packets.PacketsBpfMapSpecs{}))
	assert.Equal(t, tagNames, constants,
		"packet bpf2go PacketsMap* constants must match PacketsMapSpecs ebpf tags")

	for _, name := range constants {
		assert.Contains(t, spec.Maps, name, "packet BPF object must define map %q", name)
	}
}

func TestFlowMapNamesMatchBytecodeManifest(t *testing.T) {
	bcMaps, err := extractBcMkMapNames("../../.mk/bc.mk", "FLOW_MAPS")
	require.NoError(t, err, "failed to extract map names from .mk/bc.mk")

	tagNames := mapNamesFromEBPFTags(reflect.TypeOf(flows.FlowsBpfMapSpecs{}))
	sort.Strings(bcMaps)

	assert.Equal(t, tagNames, bcMaps,
		"flow bpf2go map spec tags must match .mk/bc.mk FLOW_MAPS block; update bc.mk when adding or removing flow maps")
}

func TestPacketMapNamesMatchBytecodeManifest(t *testing.T) {
	bcMaps, err := extractBcMkMapNames("../../.mk/bc.mk", "PACKET_MAPS")
	require.NoError(t, err, "failed to extract map names from .mk/bc.mk")

	tagNames := mapNamesFromEBPFTags(reflect.TypeOf(packets.PacketsBpfMapSpecs{}))
	sort.Strings(bcMaps)

	assert.Equal(t, tagNames, bcMaps,
		"packet bpf2go map spec tags must match .mk/bc.mk PACKET_MAPS block; update bc.mk when adding or removing packet maps")
}

func mapNamesFromEBPFTags(typ reflect.Type) []string {
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Tag.Get("ebpf"); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func bpfDataMapNames[V any](maps map[string]V) []string {
	names := make([]string, 0, len(maps))
	for name := range maps {
		if strings.HasPrefix(name, ".") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func extractBcMkMapNames(filePath, defineName string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	mapsRegex := regexp.MustCompile(`define ` + defineName + `\s*\n((.|\s)*?)\nendef`)
	matches := mapsRegex.FindStringSubmatch(string(content))
	if len(matches) < 2 {
		return nil, fmt.Errorf("could not find %s definition in %s", defineName, filePath)
	}

	jsonContent := strings.TrimSpace(matches[1])

	var mapsData map[string]string
	if err := json.Unmarshal([]byte(jsonContent), &mapsData); err != nil {
		return nil, err
	}

	mapNames := make([]string, 0, len(mapsData))
	for mapName := range mapsData {
		mapNames = append(mapNames, mapName)
	}

	return mapNames, nil
}
