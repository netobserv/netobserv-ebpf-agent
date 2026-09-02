package tlsprofile

import (
	"bytes"
	"crypto/tls"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestMinVersionFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		expected    uint16
		expectedSet bool
		expectErr   bool
	}{
		{name: "absent", value: "", expected: 0, expectedSet: false},
		{name: "valid TLS1.2", value: "771", expected: tls.VersionTLS12, expectedSet: true},
		{name: "valid TLS1.3", value: "772", expected: tls.VersionTLS13, expectedSet: true},
		{name: "malformed", value: "not-a-number", expectErr: true},
		{name: "out of uint16 range", value: "99999999", expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Always set (even to "", which the code treats the same as absent)
			// so a TLS_MIN_VERSION inherited from the parent environment can't
			// make this test nondeterministic.
			t.Setenv(EnvMinVersion, tt.value)
			v, set, err := minVersionFromEnv()
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, v)
			assert.Equal(t, tt.expectedSet, set)
		})
	}
}

func TestCipherSuitesFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		expected  []uint16
		expectErr bool
	}{
		{name: "absent", value: "", expected: nil},
		{name: "single valid", value: "49199", expected: []uint16{49199}},
		{name: "multiple valid with spaces", value: " 49199 , 49200 ", expected: []uint16{49199, 49200}},
		{name: "one malformed entry fails the whole list", value: "49199,not-a-number,49200", expectErr: true},
		{name: "all malformed", value: "abc,def", expectErr: true},
		{name: "empty entries ignored", value: "49199,,49200", expected: []uint16{49199, 49200}},
		{name: "TLS 1.3 suite IDs filtered out", value: "4865,49199,4866,4867", expected: []uint16{49199}},
		{name: "TLS 1.3-only suite IDs yield nil", value: "4865,4866,4867", expected: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Always set, so a TLS_CIPHER_SUITES inherited from the parent
			// environment can't make this test nondeterministic.
			t.Setenv(EnvCipherSuites, tt.value)
			suites, err := cipherSuitesFromEnv()
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, suites)
		})
	}
}

func TestCurvePrefsFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		expected  []tls.CurveID
		expectErr bool
	}{
		{name: "absent", value: "", expected: nil},
		{name: "single valid", value: "23", expected: []tls.CurveID{tls.CurveP256}},
		{name: "multiple valid", value: "23,24", expected: []tls.CurveID{tls.CurveP256, tls.CurveP384}},
		{name: "one malformed entry fails the whole list", value: "23,bogus,24", expectErr: true},
		{name: "all malformed", value: "bogus,also-bogus", expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Always set, so a TLS_CURVE_PREFERENCES inherited from the
			// parent environment can't make this test nondeterministic.
			t.Setenv(EnvCurvePreferences, tt.value)
			curves, err := curvePrefsFromEnv()
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, curves)
		})
	}
}

func TestApply_NilConfig(t *testing.T) {
	assert.NotPanics(t, func() { _ = Apply(nil) })
	assert.NoError(t, Apply(nil))
}

func TestApply_NoEnvLeavesConfigUnchanged(t *testing.T) {
	// Explicitly clear all three vars: a TLS_* value inherited from the
	// parent environment must not make this test nondeterministic.
	t.Setenv(EnvMinVersion, "")
	t.Setenv(EnvCipherSuites, "")
	t.Setenv(EnvCurvePreferences, "")

	c := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{49199},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
	assert.NoError(t, Apply(c))
	assert.Equal(t, uint16(tls.VersionTLS13), c.MinVersion)
	assert.Equal(t, []uint16{49199}, c.CipherSuites)
	assert.Equal(t, []tls.CurveID{tls.CurveP256}, c.CurvePreferences)
}

func TestApply_ValidOverrides(t *testing.T) {
	t.Setenv(EnvMinVersion, "771")
	t.Setenv(EnvCipherSuites, "49199,49200")
	t.Setenv(EnvCurvePreferences, "23,24")

	c := &tls.Config{MinVersion: tls.VersionTLS13}
	assert.NoError(t, Apply(c))

	assert.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
	assert.Equal(t, []uint16{49199, 49200}, c.CipherSuites)
	assert.Equal(t, []tls.CurveID{tls.CurveP256, tls.CurveP384}, c.CurvePreferences)
}

func TestApply_PartiallyMalformedOverridesLeavesConfigUntouched(t *testing.T) {
	// MinVersion malformed; cipher suites otherwise valid; curve preferences absent.
	// Because one field is invalid, none of the fields should be applied.
	t.Setenv(EnvMinVersion, "not-a-number")
	t.Setenv(EnvCipherSuites, "49199,49200")

	c := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{9999},
		CurvePreferences: []tls.CurveID{tls.CurveP384},
	}
	err := Apply(c)

	assert.Error(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), c.MinVersion, "no field should be overridden when any override is invalid")
	assert.Equal(t, []uint16{9999}, c.CipherSuites, "no field should be overridden when any override is invalid")
	assert.Equal(t, []tls.CurveID{tls.CurveP384}, c.CurvePreferences, "no field should be overridden when any override is invalid")
}

func TestApply_MalformedCipherSuiteLeavesConfigUntouched(t *testing.T) {
	t.Setenv(EnvMinVersion, "771")
	t.Setenv(EnvCipherSuites, "49199,garbage")

	c := &tls.Config{MinVersion: tls.VersionTLS13}
	err := Apply(c)

	assert.Error(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), c.MinVersion, "valid min version should not be applied when cipher suites are invalid")
}

// TestApply_OpenShiftModernProfile reproduces the env vars netobserv-operator
// derives from OpenShift's "Modern" TLSSecurityProfile, whose Ciphers list is
// exactly the three TLS 1.3 suite names (they're included there deliberately
// by openshift/library-go, even though Go's crypto/tls never reads them from
// CipherSuites). This must not fail the whole profile application.
func TestApply_OpenShiftModernProfile(t *testing.T) {
	var buf bytes.Buffer
	orig := logrus.StandardLogger().Out
	logrus.SetOutput(&buf)
	t.Cleanup(func() { logrus.SetOutput(orig) })

	t.Setenv(EnvMinVersion, "772")
	t.Setenv(EnvCipherSuites, "4865,4866,4867")
	t.Setenv(EnvCurvePreferences, "")

	c := &tls.Config{}
	err := Apply(c)

	assert.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), c.MinVersion)
	assert.Empty(t, c.CipherSuites, "an all-TLS-1.3 cipher list has nothing to apply")
	assert.Contains(t, buf.String(), EnvCipherSuites, "the (harmless) TLS_CIPHER_SUITES override should still be noted")
}

// TestApply_OpenShiftIntermediateProfile reproduces OpenShift's "Intermediate"
// TLSSecurityProfile, whose Ciphers list mixes the three TLS 1.3 suite names
// with real TLS 1.2 suites: the TLS 1.3 ones must be filtered out, and the
// TLS 1.2 ones applied.
func TestApply_OpenShiftIntermediateProfile(t *testing.T) {
	t.Setenv(EnvMinVersion, "771")
	t.Setenv(EnvCipherSuites, "4865,4866,4867,49199,49200")
	t.Setenv(EnvCurvePreferences, "")

	c := &tls.Config{}
	err := Apply(c)

	assert.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
	assert.Equal(t, []uint16{49199, 49200}, c.CipherSuites)
}

func TestApply_WarnsWhenCipherSuitesInertUnderTLS13(t *testing.T) {
	var buf bytes.Buffer
	orig := logrus.StandardLogger().Out
	logrus.SetOutput(&buf)
	t.Cleanup(func() { logrus.SetOutput(orig) })

	t.Setenv(EnvMinVersion, "")
	t.Setenv(EnvCipherSuites, "49199,49200")
	t.Setenv(EnvCurvePreferences, "")

	c := &tls.Config{MinVersion: tls.VersionTLS13}
	err := Apply(c)

	assert.NoError(t, err)
	assert.Empty(t, c.CipherSuites, "cipher suites are not applied at all when the effective TLS version is already 1.3")
	assert.Contains(t, buf.String(), EnvCipherSuites)
	assert.Contains(t, buf.String(), "no effect")
}

func TestApply_NoWarningWhenEffectiveVersionAllowsTLS12(t *testing.T) {
	var buf bytes.Buffer
	orig := logrus.StandardLogger().Out
	logrus.SetOutput(&buf)
	t.Cleanup(func() { logrus.SetOutput(orig) })

	t.Setenv(EnvMinVersion, "771") // TLS 1.2: cipher suites remain meaningful
	t.Setenv(EnvCipherSuites, "49199")
	t.Setenv(EnvCurvePreferences, "")

	c := &tls.Config{MinVersion: tls.VersionTLS13}
	err := Apply(c)

	assert.NoError(t, err)
	assert.NotContains(t, buf.String(), EnvCipherSuites)
}
