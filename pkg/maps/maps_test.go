package maps

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapNamesMatchEBPFDefinitions(t *testing.T) {
	// Extract map names from netobserv-ebpf-agent/pkg/ebpf
	ebpfMaps := extractEBPFMapNames()

	// Get map names from our package
	packageMaps := Maps

	// Sort both slices for comparison
	sort.Strings(ebpfMaps)
	sort.Strings(packageMaps)
	fmt.Printf("eBPF maps: %+v\n", ebpfMaps)
	fmt.Printf("Package maps: %+v\n", packageMaps)

	// Verify they match
	assert.Equal(t, ebpfMaps, packageMaps,
		"Map names in pkg/maps/maps.go do not match eBPF definitions in bpf/maps_definition.h")
}

func TestMapNamesMatchBcMk(t *testing.T) {
	// Extract map names from .mk/bc.mk
	bcMaps, err := extractBcMkMapNames("../../.mk/bc.mk")
	require.NoError(t, err, "Failed to extract map names from .mk/bc.mk")

	// Get map names from our package
	packageMaps := Maps

	// Sort both slices for comparison
	sort.Strings(bcMaps)
	sort.Strings(packageMaps)
	fmt.Printf("bc.mk maps: %+v\n", bcMaps)
	fmt.Printf("Package maps: %+v\n", packageMaps)

	// Verify they match
	assert.Equal(t, bcMaps, packageMaps,
		"Map names in pkg/maps/maps.go do not match definitions in .mk/bc.mk.\n"+
			"If you've added/removed maps, please update both files.")
}

// extractBcMkMapNames parses the .mk/bc.mk file and extracts map names from the MAPS JSON
func extractBcMkMapNames(filePath string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Find the MAPS definition block
	mapsRegex := regexp.MustCompile(`define MAPS\s*\n((.|\s)*?)\nendef`)
	matches := mapsRegex.FindStringSubmatch(string(content))

	if len(matches) < 2 {
		return nil, errors.New("Could not find MAPS definition in .mk/bc.mk")
	}

	// Extract the JSON content
	jsonContent := strings.TrimSpace(matches[1])

	// Parse JSON to extract map names
	var mapsData map[string]string
	if err := json.Unmarshal([]byte(jsonContent), &mapsData); err != nil {
		return nil, err
	}

	// Extract just the map names (keys)
	var mapNames []string
	for mapName := range mapsData {
		mapNames = append(mapNames, mapName)
	}

	return mapNames, nil
}

// extractEBPFMapNames extracts map names from the compiled eBPF agent
func extractEBPFMapNames() []string {
	var maps []string
	mapType := reflect.ValueOf(ebpf.BpfMapSpecs{})
	for i := 0; i < mapType.NumField(); i++ {
		val := reflect.Indirect(mapType)
		mapName := val.Type().Field(i).Tag.Get("ebpf")

		if mapName != "" {
			maps = append(maps, mapName)
		}
	}

	return maps
}
