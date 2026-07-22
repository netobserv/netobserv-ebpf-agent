package tlsprofile

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	EnvMinVersion       = "TLS_MIN_VERSION"
	EnvCipherSuites     = "TLS_CIPHER_SUITES"
	EnvCurvePreferences = "TLS_CURVE_PREFERENCES"
)

// Apply overrides fields in c using values from TLS_MIN_VERSION, TLS_CIPHER_SUITES
// and TLS_CURVE_PREFERENCES environment variables, when those are set.
// Values are decimal uint16 strings (e.g. "771" for TLS 1.2).
// Fields whose env var is absent are left unchanged.
func Apply(c *tls.Config) {
	if c == nil {
		return
	}
	if v := minVersionFromEnv(); v != 0 {
		c.MinVersion = v
	}
	if suites := cipherSuitesFromEnv(); len(suites) > 0 {
		c.CipherSuites = suites
	}
	if curves := curvePrefsFromEnv(); len(curves) > 0 {
		c.CurvePreferences = curves
	}
}

func minVersionFromEnv() uint16 {
	s := strings.TrimSpace(os.Getenv(EnvMinVersion))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tlsprofile: invalid %s value %q, ignoring: %v\n", EnvMinVersion, s, err)
		return 0
	}
	return uint16(v)
}

func cipherSuitesFromEnv() []uint16 {
	s := strings.TrimSpace(os.Getenv(EnvCipherSuites))
	if s == "" {
		return nil
	}
	var ids []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tlsprofile: invalid cipher suite %q in %s, skipping: %v\n", part, EnvCipherSuites, err)
			continue
		}
		ids = append(ids, uint16(v))
	}
	return ids
}

func curvePrefsFromEnv() []tls.CurveID {
	s := strings.TrimSpace(os.Getenv(EnvCurvePreferences))
	if s == "" {
		return nil
	}
	var curves []tls.CurveID
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tlsprofile: invalid curve %q in %s, skipping: %v\n", part, EnvCurvePreferences, err)
			continue
		}
		curves = append(curves, tls.CurveID(v))
	}
	return curves
}
