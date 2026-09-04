package plaintext

// MaxPlaintextCaptureBytes matches bpf MAX_DATA_SIZE_OPENSSL (16 KiB).
const MaxPlaintextCaptureBytes = 16 * 1024

// PreviewLength returns how many payload bytes to expose in PlaintextPreview.
// configured == 0 means the full captured payload. Positive values cap the preview.
func PreviewLength(configured, dataLen int) int {
	if dataLen <= 0 {
		return 0
	}
	if configured == 0 {
		return dataLen
	}
	n := configured
	if n > MaxPlaintextCaptureBytes {
		n = MaxPlaintextCaptureBytes
	}
	if n > dataLen {
		return dataLen
	}
	return n
}
