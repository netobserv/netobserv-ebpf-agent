package plaintext

import "testing"

func TestPreviewLength(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		dataLen    int
		want       int
	}{
		{"default cap", 256, 512, 256},
		{"full when zero", 0, 512, 512},
		{"full when zero short", 0, 12, 12},
		{"empty data", 256, 0, 0},
		{"shorter than cap", 256, 40, 40},
		{"custom cap", 1024, 2048, 1024},
		{"max capture bound", MaxPlaintextCaptureBytes + 1, MaxPlaintextCaptureBytes + 100, MaxPlaintextCaptureBytes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PreviewLength(tt.configured, tt.dataLen); got != tt.want {
				t.Fatalf("PreviewLength(%d, %d) = %d, want %d", tt.configured, tt.dataLen, got, tt.want)
			}
		})
	}
}
