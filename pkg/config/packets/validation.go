package packets

import "fmt"

// Validate rejects packet-capture-only options in flow mode.
func Validate(f Features) error {
	if f.EnablePCA {
		return fmt.Errorf("ENABLE_PCA is only valid in packet capture mode")
	}
	return nil
}
