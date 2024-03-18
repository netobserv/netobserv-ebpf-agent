package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIskernelOlderthan514(t *testing.T) {
	tests := []struct {
		name          string
		kernelVersion string
		want          bool
		wantError     bool
	}{
		{
			name:          "Kernel version < 5.14.0",
			kernelVersion: "5.13.0",
			want:          true,
		},
		{
			name:          "Kernel version = 5.14.0",
			kernelVersion: "5.14.0",
			want:          false,
		},
		{
			name:          "Kernel version > 5.14.0",
			kernelVersion: "5.15.0",
			want:          false,
		},
		{
			name:          "Error getting kernel version",
			kernelVersion: "invalid version",
			want:          false,
			wantError:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versionUint, err := kernelVersionFromReleaseString(tt.kernelVersion)
			if tt.wantError {
				require.Errorf(t, err, "%s: expecting error, got none", tt.name)
			} else {
				require.NoErrorf(t, err, "%s: expecting no error, got %v", tt.name, err)
			}
			kernelVersion = versionUint
			got := IsKernelOlderThan("5.14.0")
			if got != tt.want {
				t.Errorf("%s: IskernelOlderthan514() = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
