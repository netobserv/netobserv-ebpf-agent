package tlsprofile

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	EnvMinVersion       = "TLS_MIN_VERSION"
	EnvCipherSuites     = "TLS_CIPHER_SUITES"
	EnvCurvePreferences = "TLS_CURVE_PREFERENCES"
)

// Apply overrides fields in c using values from TLS_MIN_VERSION, TLS_CIPHER_SUITES
// and TLS_CURVE_PREFERENCES environment variables, when those are set.
// Values are decimal uint16 strings (e.g. "771" for TLS 1.2, "772" for TLS 1.3),
// or, for cipher suites/curves, the corresponding IANA TLS registry IDs.
// Env vars that are absent leave the corresponding field unchanged.
// If any set env var holds a value that isn't a valid uint16, c is left
// entirely unmodified and an error describing the first invalid value is
// returned; no further validation (e.g. against known curve IDs) is
// performed, so it is the caller's responsibility to supply correct IDs.
// TLS_CIPHER_SUITES silently filters out the fixed TLS 1.3 suite IDs
// (4865, 4866, 4867): crypto/tls.Config.CipherSuites only affects TLS 1.0-1.2
// negotiation, so those IDs would never do anything there, and standard TLS
// profiles (e.g. OpenShift's Intermediate/Modern) legitimately include them
// alongside real TLS 1.0-1.2 suite IDs.
// If TLS_CIPHER_SUITES is set but the effective MinVersion is TLS 1.3, a
// warning is logged: Go's crypto/tls does not allow customizing the (fixed,
// already secure) TLS 1.3 cipher suite list, so the override has no effect
// unless a lower TLS version ends up being negotiated.
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
		if c.MinVersion >= tls.VersionTLS13 {
			logrus.Warnf("tlsprofile: %s is set but has no effect because the effective minimum TLS version is 1.3 (TLS 1.3 cipher suites are not configurable)", EnvCipherSuites)
		}
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

// tls13CipherSuiteIDs are the fixed suite IDs Go's crypto/tls negotiates
// automatically for TLS 1.3 connections. tls.Config.CipherSuites only affects
// TLS 1.0-1.2 negotiation, so these IDs have no effect there; they are
// silently filtered out rather than rejected because standard TLS profile
// definitions (e.g. OpenShift's Intermediate/Modern TLSSecurityProfile)
// legitimately list them alongside real TLS 1.0-1.2 suite IDs.
var tls13CipherSuiteIDs = map[uint16]struct{}{
	4865: {}, // TLS_AES_128_GCM_SHA256
	4866: {}, // TLS_AES_256_GCM_SHA384
	4867: {}, // TLS_CHACHA20_POLY1305_SHA256
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
		id := uint16(v)
		if _, ok := tls13CipherSuiteIDs[id]; ok {
			continue
		}
		ids = append(ids, id)
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
