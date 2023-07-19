package utils

import (
	"errors"
	"testing"
)

func TestIskernelOlderthan514(t *testing.T) {
	tests := []struct {
		name              string
		mockKernelVersion func() (uint32, error)
		want              bool
	}{
		{
			name: "Kernel version < 5.14.0",
			mockKernelVersion: func() (uint32, error) {
				return kernelVersionFromReleaseString("5.13.0")
			},
			want: true,
		},
		{
			name: "Kernel version = 5.14.0",
			mockKernelVersion: func() (uint32, error) {
				return kernelVersionFromReleaseString("5.14.0")
			},
			want: false,
		},
		{
			name: "Kernel version > 5.14.0",
			mockKernelVersion: func() (uint32, error) {
				return kernelVersionFromReleaseString("5.15.0")
			},
			want: false,
		},
		{
			name: "Error getting kernel version",
			mockKernelVersion: func() (uint32, error) {
				return 0, errors.New("error")
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getCurrentKernelVersion = tt.mockKernelVersion
			got := IskernelOlderthan514()
			if got != tt.want {
				t.Errorf("%s: IskernelOlderthan514() = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
