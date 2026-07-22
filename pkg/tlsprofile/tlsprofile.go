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
// Env vars that are absent leave the corresponding field unchanged.
// If any set env var holds an invalid value, c is left entirely unmodified
// and an error describing the first invalid value is returned.
func Apply(c *tls.Config) error {
	if c == nil {
		return nil
	}
	minVersion, hasMinVersion, err := minVersionFromEnv()
	if err != nil {
		return fmt.Errorf("apply TLS profile: %w", err)
	}
	suites, err := cipherSuitesFromEnv()
	if err != nil {
		return fmt.Errorf("apply TLS profile: %w", err)
	}
	curves, err := curvePrefsFromEnv()
	if err != nil {
		return fmt.Errorf("apply TLS profile: %w", err)
	}

	if hasMinVersion {
		c.MinVersion = minVersion
	}
	if suites != nil {
		c.CipherSuites = suites
	}
	if curves != nil {
		c.CurvePreferences = curves
	}
	return nil
}

func minVersionFromEnv() (value uint16, set bool, err error) {
	s := strings.TrimSpace(os.Getenv(EnvMinVersion))
	if s == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false, fmt.Errorf("tlsprofile: invalid %s value %q: %w", EnvMinVersion, s, err)
	}
	return uint16(v), true, nil
}

func cipherSuitesFromEnv() ([]uint16, error) {
	s := strings.TrimSpace(os.Getenv(EnvCipherSuites))
	if s == "" {
		return nil, nil
	}
	var ids []uint16
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("tlsprofile: invalid cipher suite %q in %s: %w", part, EnvCipherSuites, err)
		}
		ids = append(ids, uint16(v))
	}
	return ids, nil
}

func curvePrefsFromEnv() ([]tls.CurveID, error) {
	s := strings.TrimSpace(os.Getenv(EnvCurvePreferences))
	if s == "" {
		return nil, nil
	}
	var curves []tls.CurveID
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("tlsprofile: invalid curve %q in %s: %w", part, EnvCurvePreferences, err)
		}
		curves = append(curves, tls.CurveID(v))
	}
	return curves, nil
}
