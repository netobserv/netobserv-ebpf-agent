package packets

import "time"

// Features holds packet-capture-only configuration options.
type Features struct {
	// EnablePCA enables Packet Capture Agent (PCA). By default, PCA is off.
	EnablePCA bool `env:"ENABLE_PCA" envDefault:"false"`
	// TLSPlaintextPIDAllowlist optional comma-separated PIDs to scope TLS plaintext capture
	TLSPlaintextPIDAllowlist string `env:"TLS_PLAINTEXT_PID_ALLOWLIST"`
	// TLSPlaintextDedupEnabled drops duplicate plaintext events within the dedup window
	TLSPlaintextDedupEnabled bool `env:"TLS_PLAINTEXT_DEDUP_ENABLED" envDefault:"true"`
	// TLSPlaintextDedupWindow time window for plaintext deduplication
	TLSPlaintextDedupWindow time.Duration `env:"TLS_PLAINTEXT_DEDUP_WINDOW" envDefault:"500ms"`
	// TLSPlaintextMinBytes drops plaintext events shorter than this length (0 = disabled)
	TLSPlaintextMinBytes int `env:"TLS_PLAINTEXT_MIN_BYTES" envDefault:"0"`
	// TLSPlaintextPreviewBytes limits PlaintextPreview length (0 = full captured payload, default 256)
	TLSPlaintextPreviewBytes int `env:"TLS_PLAINTEXT_PREVIEW_BYTES" envDefault:"256"`
}
