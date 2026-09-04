package packets

// Features holds packet-capture-only configuration options.
type Features struct {
	// EnablePCA enables Packet Capture Agent (PCA). By default, PCA is off.
	EnablePCA bool `env:"ENABLE_PCA" envDefault:"false"`
}
