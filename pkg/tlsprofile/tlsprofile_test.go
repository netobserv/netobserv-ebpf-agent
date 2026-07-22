package tlsprofile

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinVersionFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		set         bool
		expected    uint16
		expectedSet bool
		expectErr   bool
	}{
		{name: "absent", set: false, expected: 0, expectedSet: false},
		{name: "empty", value: "", set: true, expected: 0, expectedSet: false},
		{name: "valid TLS1.2", value: "771", set: true, expected: tls.VersionTLS12, expectedSet: true},
		{name: "valid TLS1.3", value: "772", set: true, expected: tls.VersionTLS13, expectedSet: true},
		{name: "malformed", value: "not-a-number", set: true, expectErr: true},
		{name: "out of uint16 range", value: "99999999", set: true, expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(EnvMinVersion, tt.value)
			}
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
		set       bool
		expected  []uint16
		expectErr bool
	}{
		{name: "absent", set: false, expected: nil},
		{name: "empty", value: "", set: true, expected: nil},
		{name: "single valid", value: "4865", set: true, expected: []uint16{4865}},
		{name: "multiple valid with spaces", value: " 4865 , 4866 ", set: true, expected: []uint16{4865, 4866}},
		{name: "one malformed entry fails the whole list", value: "4865,not-a-number,4867", set: true, expectErr: true},
		{name: "all malformed", value: "abc,def", set: true, expectErr: true},
		{name: "empty entries ignored", value: "4865,,4867", set: true, expected: []uint16{4865, 4867}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(EnvCipherSuites, tt.value)
			}
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
		set       bool
		expected  []tls.CurveID
		expectErr bool
	}{
		{name: "absent", set: false, expected: nil},
		{name: "empty", value: "", set: true, expected: nil},
		{name: "single valid", value: "23", set: true, expected: []tls.CurveID{tls.CurveP256}},
		{name: "multiple valid", value: "23,24", set: true, expected: []tls.CurveID{tls.CurveP256, tls.CurveP384}},
		{name: "one malformed entry fails the whole list", value: "23,bogus,24", set: true, expectErr: true},
		{name: "all malformed", value: "bogus,also-bogus", set: true, expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(EnvCurvePreferences, tt.value)
			}
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
	c := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{4865},
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
	assert.NoError(t, Apply(c))
	assert.Equal(t, uint16(tls.VersionTLS13), c.MinVersion)
	assert.Equal(t, []uint16{4865}, c.CipherSuites)
	assert.Equal(t, []tls.CurveID{tls.CurveP256}, c.CurvePreferences)
}

func TestApply_ValidOverrides(t *testing.T) {
	t.Setenv(EnvMinVersion, "771")
	t.Setenv(EnvCipherSuites, "4865,4866")
	t.Setenv(EnvCurvePreferences, "23,24")

	c := &tls.Config{MinVersion: tls.VersionTLS13}
	assert.NoError(t, Apply(c))

	assert.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
	assert.Equal(t, []uint16{4865, 4866}, c.CipherSuites)
	assert.Equal(t, []tls.CurveID{tls.CurveP256, tls.CurveP384}, c.CurvePreferences)
}

func TestApply_PartiallyMalformedOverridesLeavesConfigUntouched(t *testing.T) {
	// MinVersion malformed; cipher suites otherwise valid; curve preferences absent.
	// Because one field is invalid, none of the fields should be applied.
	t.Setenv(EnvMinVersion, "not-a-number")
	t.Setenv(EnvCipherSuites, "4865,4866")

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
	t.Setenv(EnvCipherSuites, "4865,garbage")

	c := &tls.Config{MinVersion: tls.VersionTLS13}
	err := Apply(c)

	assert.Error(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), c.MinVersion, "valid min version should not be applied when cipher suites are invalid")
}
