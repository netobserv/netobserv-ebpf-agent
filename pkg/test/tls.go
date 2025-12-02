package test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Fake certificates / private keys for test

// CA generated with:
// openssl req -newkey rsa:2048 -nodes -days 3650 -x509 -keyout ca.key -out ca.crt -subj "/CN=*"
const caCert string = `-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIULGvHF3aRgJryhvb/9lQMR8TPpIYwDQYJKoZIhvcNAQEL
BQAwDDEKMAgGA1UEAwwBKjAeFw0yMzA4MDIwODUzMTdaFw0zMzA3MzAwODUzMTda
MAwxCjAIBgNVBAMMASowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK
NcqKT0leAUzpkmp0x7PYGXvGSXviN7zbo415he1mIYWvuGBhB2J3aUlafABJ2wxD
tdjXFDUI2T9BjRDrbsha4LzhzeBFc3xorlp/KDVZnhgbbHeCL8bfgQrfjsFzAXNa
QEdoTwBRs8fznXVzQ7ecWhobyT9M84v2Mlh93YQFEueiHx0Z8jFUESn6vcOXWXqF
8VZWlPPsRauy79zFkCmr09UKxyOWGtImM+9Sgvda7oZGkJBZ1gvhBULOG72ekhsH
RtlT4Xmf4irINm4vRnZcFRJgwaOsCvX/9gyDCfoJ0ioUZ5ZmhYNGJeNSi63LnAZm
1Zsa4ZOGvtdsdAgaZN1jAgMBAAGjUzBRMB0GA1UdDgQWBBQ34SoDX/LC+i2h57cI
aOGmGZTgBzAfBgNVHSMEGDAWgBQ34SoDX/LC+i2h57cIaOGmGZTgBzAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBfFSuPYJK0Gt8psgARSHLJUzSB
X9XmcIYpeFIZk5GqmGnj/0op4w3R/T/TwYTf7+FvqGIKaMyXSgeJJu1uC1M/AI11
nQmv9XtLmX2BJtKWORoBOPYKnoGSaljoQJZzJJ09lzasHLy68cYezbqb+3+EIGEa
vBKdFgbDyYQpSIs3oAIW9drcEywFf8s5ZSewPhaz1byDlvTHJjKNGoWwm/tlXhv/
GXHWiYftbJRGHDiA9BqZT2g/vMz/1e9k5wSek+fqaBQNS7nEijUz+Qk0LlmagZV3
kom8Fkz5HTYkmZVzXPW8spFEuIibCgRK1qA1RuDsyNxMnk3c1jcR8B5AJ/VI
-----END CERTIFICATE-----`

// Client key (for mTLS) generated with:
// openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/C=GB/ST=London/L=London/O=libvault consultants/OU=IT Department/CN=*"
const clientKey string = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6MwSpGNZz7sCO
/6Wn+iC7Am+UxQkfm+SWHDxRB9wgDQbZVesAFWiRkMXcTQjBc/71R2RhZed1FFVO
vXZfewfgepdq9RlRCEgFSoMhF8zuwxwKfrrAML2PiRy720i0azwLLilTQB9s5MrB
Cz0Gsq2neY6wXf3KkyMYyhzBaKocl5NqxIcHILWJ+jBnKrfvW69CP8jtIjZLo9xS
WtCw0S2pTVRBt16smiA8VNfXnZc2p8LyWCmZ523AjqKnatviiJ6apyTlhsLMx9Lf
RIqkirgaoTB9y6VFvyZQtqXD+PI7r9QykVgHioMnep2gsJwgxqTuj75gxTsebIJd
PKdv4qwTAgMBAAECggEAUSsWWAR8z/L/PBcThsNR61PngknWbVIO9qT+YjBz9ADZ
wHpkxBeRCwu6RQvLylEfjpr9ljvPB0nC2l1bMco3J9MpGLYZwCpFAxF1UkLG0jp5
idWu4UMeD2ks/nNcIVIxzYnk9+aXDGg8PqUAiF/xtXUXD6kZjmpPvWm12VYf+fAX
OIXrs3BDJKsJUDfOxg8ujcOuK+qyQjVOoiR8zrREZy/fCRc0TSD7tnnLLPW5MCst
PaFhS8vb35XuTvzCW7yCdosV/xnf2I22KWVJDxV11xtfbi3AF8ggyzUZElW8fVCz
7AJU3W95NVArNw3mvSm6vTcdbddQbuJsMnW1Hc2YCQKBgQDaBUlnliOpTUAGxCOV
sLl7GjsMfH8TrsHa9+ca0BwcoSqDky0jGh/sm1LgyPqoHn9Vj8uK/DLebNMnRZAc
KzGMQpzneW7K0G64SHJI6Faa29FTUfa+azeS3vIKa6WbTWzuhGQ/R7OqTy7UbJTs
IQaA/vfPa13ZNWtHONAaMO96PQKBgQDaoqVVv9NZIVCK1PlcdHhjJ++NrWkKgBGk
YaMvXbWRP0vF1vEgKIE8vzNufQiw6FuiZgeLQluglN6wkvV3fzhVnu7An8DqVaxD
JQQAuwHTvn3wmiepMuYNleYU67bAeFhNZRJuOmkUtrLiPOgVliuwNUqmaaUnzouD
RLzFs/00jwKBgQCLcqI2zUNWAIEZUs7n6bdZU7e9DsxBDKAVrEZ3UfEJJtSIf9R5
BTayIc7q0+HvMkKDuYuZBCKNPdH45nd8bOwuKFUvgO4qbxLCcCQZGfJ67mp+/ofx
16YeHNd3bs7n/KfWD3wHNZdnMWpkmGbQeXctfueGFchbK93IGkCQ4AfsiQKBgHEH
bsRC9Gd6wqHTcsrqZ6aTadPr14cXKIe79loxbwGVIH46HdRLPG0ER/mR6GFU7rKp
XrMO7kG5VNsiToalnaEeFj49GMXM3s6jn0slYs9uBrvRZjmh168kVJtyNLuSO8xf
OUUFK3gK77XoWO94AEQLePlJWpmWvSdy7MikwX1fAoGALrRIZVmlmDoJ/jm9lNaZ
r3PmRWYlhqLyI/oeEzczqy6WOGcTOQsXlP4Yu1EM6V9mLqQ4ATZ2lUM3mcahfi14
RPYzuPxqdxxmRGy1iPVWwU7Jw97ke80Zx68Wm69sQHb8Gz9Y6B3c/F63WMuojyas
APnsbr5Kx+5wC0t3xGfShK4=
-----END PRIVATE KEY-----`

// Client cert (for mTLS) generated with:
// openssl x509 -req -days 3650 -sha256 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -extfile <(echo subjectAltName = IP:127.0.0.1)
const clientCert string = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUZP3uzJrPArjETkLd2SZticeIAeMwDQYJKoZIhvcNAQEL
BQAwDDEKMAgGA1UEAwwBKjAeFw0yMzA4MDIwODU1NTJaFw0zMzA3MzAwODU1NTJa
MHIxCzAJBgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRv
bjEdMBsGA1UECgwUbGlidmF1bHQgY29uc3VsdGFudHMxFjAUBgNVBAsMDUlUIERl
cGFydG1lbnQxCjAIBgNVBAMMASowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC6MwSpGNZz7sCO/6Wn+iC7Am+UxQkfm+SWHDxRB9wgDQbZVesAFWiRkMXc
TQjBc/71R2RhZed1FFVOvXZfewfgepdq9RlRCEgFSoMhF8zuwxwKfrrAML2PiRy7
20i0azwLLilTQB9s5MrBCz0Gsq2neY6wXf3KkyMYyhzBaKocl5NqxIcHILWJ+jBn
KrfvW69CP8jtIjZLo9xSWtCw0S2pTVRBt16smiA8VNfXnZc2p8LyWCmZ523AjqKn
atviiJ6apyTlhsLMx9LfRIqkirgaoTB9y6VFvyZQtqXD+PI7r9QykVgHioMnep2g
sJwgxqTuj75gxTsebIJdPKdv4qwTAgMBAAGjUzBRMA8GA1UdEQQIMAaHBH8AAAEw
HQYDVR0OBBYEFJXWoxXktt1SPSppKKxG9irVdZ6pMB8GA1UdIwQYMBaAFDfhKgNf
8sL6LaHntwho4aYZlOAHMA0GCSqGSIb3DQEBCwUAA4IBAQAY+8cforOMMqzuyQtm
q2fs+rd/AavSTxxOjazD+QX7vwoCjvSqBSVr53//1hFKoEE33PsQ+UpNVOkYyNo1
QuyKfhlnqJ7wfXYFWorU07qjHHc02SlQmqHTIpu0VaUxRuEbHdMhO54oJqBnLkL5
lSOGjsHAMVh/a7ET96OqZKwMwNpWZXLmVhkXkpqf21Ept8P1aweEmmkaW3WAMQ/Y
L99WlvK/Zds/xUlXcpDBOrVZwXuYqhYsjxfig5J6z3bX6o/0g+baL0CRpIz+66BF
Ks1CJYZnOX9Tb26DyBTQAUXzJMv9sJXlYF3Llhd14YfEmOeXnNkog8GflJA7GU6C
lkAS
-----END CERTIFICATE-----`

// Server key generated with:
// openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=GB/ST=London/L=London/O=libvault consultants/OU=IT Department/CN=*"
const serverKey string = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClYidsRfhbhwxx
GUZ7X7/CwltfZCof/FmrYqzsWzimr8tUWPy/AHJHo+A08ixuZMBuCn2Uh22gFaEZ
Kn3Uk8ZmGXb9IhYZxTJrYx9+ZUvBaN5g8072bbF2TCCDYhX1w9o488mSVe3vP/I/
tINuOy990fr1BkhzSoFD/xVhQMqoDN00+B8mIWJ9pstknDcAM+6Z+FfUuwzLcxx5
LogpOIGhYt+03ywXDxfuvXfRFXFGCwifcLx8XyiOchBckxLtfXioC4Q61gWE63VN
J7qyPDrdUZ/CCY5Vz+qRqsF2rlwOWPluXrWzaKzlvmCm5iQ8J58c6dHhyY8Yob8K
xHo9F56bAgMBAAECggEARgN6Hg+3FwRio4SoPnWoCErghM8yOC1MRs5013C82HAm
m5Q6l5+YQbTiJ3f4kFmNz2gYhucYZUOS2kUPVQ2kWbfhFEO4aHt/n0+s1wUKH5yG
PDP000VX8fVDdGtzUYJy4VZvmMhQ/M6s/wQr+eALeHALFmztAgXiGIemJPBZeu+c
rbAFowzdYsHpTSrh2nm0HYSoyZr87wQoQjLo0c6FqLLxYcnCvMemcg8HK4iw6I0a
vbbG61Pdg4CNy6ZgSS96+WwiixrcWoQ7CN339giRmFT2e6vulbreQtD4QzlmqtWW
su+Du3kc/9XqtJwOpyOkHyXrALMnpPC+c0WnVp76xQKBgQDa/kd79kOWzQXTKmqn
heuaKq/UTMYlGhc13KhEpXeX/r0skWMKjuvxgVacNxv4F4d2axCLmADh1UotZsDz
9Hlvq5aPn8f/VYv0CCwOrigSyv25AEAZCnk84igbiSq1TfXppJzyqYoLue2HrW4k
CHL9KviBwauePNRDv+KNZJGALQKBgQDBVLHMDF6xjsy27T4toqLz1thdiBjd/GR+
SE6+j18z/CKJVCWlRBykmJ3vxW9qAptdb86ZxmfIFnkWJTt/yEthvyfqHe6ksXED
SElOKuReUYAPJazaGS5F9TywGnsVxhwn9BtqPMy/b7WRQJowcG9zSlntjT+cn7sg
GfSB6ASO5wKBgDaiRXc5ovcWQyPBa0ZL9NFLYP5YAP70mWHIoPovRbzXwp5BzzGt
IlPn7pGedg3Y4OS8JS6OR3oP2ielgPHbxggECNXgCOc8kmPZPhSTgk/d8Jqc42Db
6g80ZMkp2UvOHVGizb0Eavot8oJs1BONQBLFC6ZjiMs7ZcFZN84KjvopAoGAYPAz
ummVbZh5o1tv6vf6lyNqF/Pu7Bfq17sv6LMA/JL3Sj6sJaLybcGsp5Yq2E/4UTCH
umlWjmheTLFclST8T0XHIMfjaici0I+FWjF9kqFxAadVdYJcxm1CAdc1UmSkp4/p
0yorS+4ab3uiFJm7+GYWk1tYwxMAhAcfp6eL6Y8CgYAMNptHbD/fL0wrXDBVWRYP
LL55dHKf6Op+c2N9/82WsaMpHQ/A8MiIn2iwQReEIjl0zk+OfvTgQEz1FEw+zZk/
kFWRLF8Hel5mv0JKz8ExZ4LHTTE8OpxvEbvP3j6A/MngpsuN73LA4i/GqrktGtiy
UYF0gdXCSiPfvXct5lwU7g==
-----END PRIVATE KEY-----`

// Server cert generated with:
// openssl x509 -req -days 3650 -sha256 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extfile <(echo subjectAltName = IP:127.0.0.1)
const serverCert string = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUZGbRxIm/HK0OiVdTzIFWmnPqttUwDQYJKoZIhvcNAQEL
BQAwDDEKMAgGA1UEAwwBKjAeFw0yMzA4MDIwODU0NTlaFw0zMzA3MzAwODU0NTla
MHIxCzAJBgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRv
bjEdMBsGA1UECgwUbGlidmF1bHQgY29uc3VsdGFudHMxFjAUBgNVBAsMDUlUIERl
cGFydG1lbnQxCjAIBgNVBAMMASowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQClYidsRfhbhwxxGUZ7X7/CwltfZCof/FmrYqzsWzimr8tUWPy/AHJHo+A0
8ixuZMBuCn2Uh22gFaEZKn3Uk8ZmGXb9IhYZxTJrYx9+ZUvBaN5g8072bbF2TCCD
YhX1w9o488mSVe3vP/I/tINuOy990fr1BkhzSoFD/xVhQMqoDN00+B8mIWJ9pstk
nDcAM+6Z+FfUuwzLcxx5LogpOIGhYt+03ywXDxfuvXfRFXFGCwifcLx8XyiOchBc
kxLtfXioC4Q61gWE63VNJ7qyPDrdUZ/CCY5Vz+qRqsF2rlwOWPluXrWzaKzlvmCm
5iQ8J58c6dHhyY8Yob8KxHo9F56bAgMBAAGjUzBRMA8GA1UdEQQIMAaHBH8AAAEw
HQYDVR0OBBYEFOdbqIlktmQGpRr9ydKkACwx/OnhMB8GA1UdIwQYMBaAFDfhKgNf
8sL6LaHntwho4aYZlOAHMA0GCSqGSIb3DQEBCwUAA4IBAQAMKfFetofRb9dFInU5
KpF3+IVwrR53UbUbNF0mnQ7aNRE7YfLPRTOV2Dp5zeOlUiO6FhK1AkCcs1RILzUM
bUwolEbgQRmMV8NPyY+0vkBQDJQYfw3bHm2NCWRKd2A0KI9rX1VpWvY3Z300zmLM
TPgRGwN4oZbQLpbI6iZ+MuaBw9c3xOuVKGI0OQybl7MM49Uk/QAf+Ltb+VD/b+NR
QtOnsqqqb3s8LlqTbYn1zM9FSX2YNRljDkElTVfzhlD2qpMvy8Ep8qrAlFcI8yZ8
HKUIvMe6pjPWHHGVkKBldRqQIOH5WoUSKjrC8koV+Kqj6PMXKquyZdvdC3bhgj4l
Pnib
-----END CERTIFICATE-----`

// CreateCACert returns paths to CA cert and the cleanup function to defer
func CreateCACert(t *testing.T) (string, func()) {
	name, cleanup, err := DumpToTemp(caCert)
	require.NoError(t, err)
	return name, cleanup
}

// CreateClientCerts returns paths to:
// - ca
// - user cert
// - user key
// and the cleanup function to defer
func CreateClientCerts(t *testing.T) (string, string, string, func()) {
	ca, cleanupCA, err := DumpToTemp(caCert)
	require.NoError(t, err)
	uc, cleanupUC, err := DumpToTemp(clientCert)
	require.NoError(t, err)
	uk, cleanupUK, err := DumpToTemp(clientKey)
	require.NoError(t, err)
	return ca, uc, uk, func() {
		cleanupCA()
		cleanupUC()
		cleanupUK()
	}
}

// CreateAllCerts returns paths to:
// - ca
// - user cert
// - user key
// - server cert
// - server key
// and the cleanup function to defer
func CreateAllCerts(t *testing.T) (string, string, string, string, string, func()) {
	ca, cleanupCA, err := DumpToTemp(caCert)
	require.NoError(t, err)
	uc, cleanupUC, err := DumpToTemp(clientCert)
	require.NoError(t, err)
	uk, cleanupUK, err := DumpToTemp(clientKey)
	require.NoError(t, err)
	sc, cleanupSC, err := DumpToTemp(serverCert)
	require.NoError(t, err)
	sk, cleanupSK, err := DumpToTemp(serverKey)
	require.NoError(t, err)
	return ca, uc, uk, sc, sk, func() {
		cleanupCA()
		cleanupUC()
		cleanupUK()
		cleanupSC()
		cleanupSK()
	}
}

func DumpToTemp(content string) (string, func(), error) {
	file, err := os.CreateTemp("", "agent-tests-")
	if err != nil {
		return "", nil, err
	}
	err = os.WriteFile(file.Name(), []byte(content), 0644)
	if err != nil {
		defer os.Remove(file.Name())
		return "", nil, err
	}
	return file.Name(), func() {
		os.Remove(file.Name())
	}, nil
}
