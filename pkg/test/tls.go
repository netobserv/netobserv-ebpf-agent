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

// CA generated with:
// openssl req -newkey rsa:2048 -nodes -days 3650 -x509 -keyout ca.key -out ca.crt -subj "/CN=*"
const clientCA string = `-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIUCStrU+idWDMcp01lWVF2cQhp0wIwDQYJKoZIhvcNAQEL
BQAwDDEKMAgGA1UEAwwBKjAeFw0yNTEyMDUxNTM1MjlaFw0zNTEyMDMxNTM1Mjla
MAwxCjAIBgNVBAMMASowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0
ldnq3a7RXZ3tyO5OmSP2Q+z1vE/IyqSPZtGopxf8vupcklClWjrJs/rojVWMjAgE
YH4EPNOQgWhZjJQaaWaaP9HuENwkkflneQ39zSKfU6hU3jV/gYjED5QNCTsbrV1J
m/y6FzdGumwCvoztXTcg6exRWkifrJkcO9Fg0CpQ3hFuJw81G18W9yFPvHAf1XPJ
8Lglbg4zFcMOMBp8Ob5L8UITV7BGaKFVmBQM8/F4sIBYDx6ACktwxpk52pLIJF1z
95dixTZjwBN9meji8hyV/IuJ5UvwwtADhRtLhB+CWcDPuu3fVPVodRoeONSg0q/1
lfaTT4fkQCz1MaZ4kochAgMBAAGjUzBRMB0GA1UdDgQWBBSdDuiQNR5nJrRm5xNV
QabgI9/xIzAfBgNVHSMEGDAWgBSdDuiQNR5nJrRm5xNVQabgI9/xIzAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvBl5AZIpq1zZDQy9QGc6SznHT
R6bGmFPZRFEtCK00NrQT1n5fHB3dWtkUqLuIcxy6tzRf+yn9rKeqASKcc/adxrMg
Gnp5hIHN94P2LdTyHhwbGTPE+zDZyDSBfhuKmGBWMqXVkjWaxdU9/YwSe+tODvSQ
BDOqYTeCOUBHbP2oESqr66dx8DYqJieaIBiH1XCaRAhk3/DcqRzgdc24Cv+zL6gn
xhdEapxmUK2mGxiOkchn0Qy8xrT5sRZRSpXbLhia1NsK6qieC0INkkvW3lpgB30p
WDFE2110hEj7aOzf4UajFrCJIONiXqbwrANp0ILtannrKuvF40ghH8ZV5+Q5
-----END CERTIFICATE-----`

// Client key (for mTLS) generated with:
// openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/C=GB/ST=London/L=London/O=libvault consultants/OU=IT Department/CN=*"
const clientKey string = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8EZEm3cXCZZ65
UXQC0iV4VA51hM0BcXKiCetNWMvSaeNwANtEQkAQ5SztfVaZkgPpSsZjzYVmFvKc
CyVTxct4vZ7Fn8Vyl2QWNXzzHcssSck7edCMOVWoITgGvPJTyrj8Q0meZ7tJ5IGk
uzdkeEPy4DD22ObGUjgScntJO65kq0xJ+Ku0Mw3s4RfHi+fsDbvRjvuQcu0y+L3t
6sJKsM0vyuWLqQKDN8SUAG3gJFLtNVK5W4H8eG72Y68vgBRXHBCTt2hesOsCAgW3
djZrDx6vFnj5fsHLEUA6T1iXcl8yL0+ALShtEjBgaOu9RlbFY3Pei7uV2fujjRSk
ihKMbQsZAgMBAAECggEAAQI5HJPA7Ud9P/IzZJZ68/fDchbpwJG6syrJc8s/oJvH
yACBLI8MZ+rKwGVVMxKo6bXodX2TMxZ5a6PVqercKgQeV2IBfZlZRJM53dXxkoW8
yhBfsXjXQEUZV1PpGtDyCAxWVz6oLv/GQDtu0x+gAav5J0HHjxW+zj6F8cEbsNeG
AL4QjIxO9RYXA+KLIu7Nx6XSsiZFyDJCM31xT5WtS6jzzMJ3wdbTotI4TQzim3au
Exh03aFnksKSmvF+txQncZeHSmJw90T6nEvUjW6dLKI3XKgTVPQVfrDh1h+qLLQA
9tuZEZgRHUCwlCtljYiS67RhBhU9cZ8IqNOpJsFQmQKBgQDj4wvVtmE/ybiDm9j5
hrw8AR4hAA2OdCmGJgRfKhCJzgd2wg/+sIFYjNadD6ULgadjaiDoaHNKCh6frGAF
PMkFk4U5jwK9QCtls/24xo8HzEFadfJEgv50iTJNAl57Z/chNhhAAaVAZlWqRTN+
D/FYMozX+bs0r37MSeGiIcSgjQKBgQDTRQJ5DNqKez/Pi8rzJaKM9YJyb6UlmIsy
IzKj7UoLyQCjzK4fo6z42QVPtQzR6J0zkdiruPeFqvrfEW+xdi+0Jy5DRGekUVrm
dX5tbcGPPZYfsu8u96gi43TJTVatQ1pKEN0+8sq8wzsSO0cfZ8nnB+iCaJUbib08
cEYiL1NPvQKBgQCBZsWrnxptvD/YC8ETP9zXPdM77enEwFVr5V6KIzqs5Z77Yoru
lo98Fs0u9llDxWWlX/g7wEPnAQQOqzUDBFcpoXD/FCP8DtoVsDUcnTNOvD9H/L2L
Bc8zoUw8ymGYNZrw8uSmQ8jwXqu6Of1ZUfg7msi7QwV4j0ay/ijvhbk/aQKBgBeA
I6hHb7/budtiV274jr5TSPFlzd8CuukW1Tk62fO5piKSUAQg9sqviVG2d/iZgXMN
FCb16kKqJEHP9LauyNunSBQfdc/nZM8h3rBZdyBx31MjWkvFLKTE3GbP/YZEabS3
b4TjCP46UUXT5jNuHh1e2dQ3we5QQgaJDqQa04+ZAoGBALTIJW/uq7y+3Dxq4oLC
mato2oHmf/8TCruwAXljdiUPgH2SCDlH/62oBes/zokS1cLk+N/5n25EiffcyviT
heaRcSqLl5Q3opyt37Jk/nDjB3+P+sCAX4EsRJl3U4M0r4ickKan+g856Tt+AQl0
NHdueneZkKeVhhtQrGu9WzM3
-----END PRIVATE KEY-----`

// Client cert (for mTLS) generated with:
// openssl x509 -req -days 3650 -sha256 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -extfile <(echo subjectAltName = IP:127.0.0.1)
const clientCert string = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUcOdT2T03jT2H/W78F/usXc4zv78wDQYJKoZIhvcNAQEL
BQAwDDEKMAgGA1UEAwwBKjAeFw0yNTEyMDUxNTM4MDhaFw0zNTEyMDMxNTM4MDha
MHIxCzAJBgNVBAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRv
bjEdMBsGA1UECgwUbGlidmF1bHQgY29uc3VsdGFudHMxFjAUBgNVBAsMDUlUIERl
cGFydG1lbnQxCjAIBgNVBAMMASowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC8EZEm3cXCZZ65UXQC0iV4VA51hM0BcXKiCetNWMvSaeNwANtEQkAQ5Szt
fVaZkgPpSsZjzYVmFvKcCyVTxct4vZ7Fn8Vyl2QWNXzzHcssSck7edCMOVWoITgG
vPJTyrj8Q0meZ7tJ5IGkuzdkeEPy4DD22ObGUjgScntJO65kq0xJ+Ku0Mw3s4RfH
i+fsDbvRjvuQcu0y+L3t6sJKsM0vyuWLqQKDN8SUAG3gJFLtNVK5W4H8eG72Y68v
gBRXHBCTt2hesOsCAgW3djZrDx6vFnj5fsHLEUA6T1iXcl8yL0+ALShtEjBgaOu9
RlbFY3Pei7uV2fujjRSkihKMbQsZAgMBAAGjUzBRMA8GA1UdEQQIMAaHBH8AAAEw
HQYDVR0OBBYEFKR8VXncy1LIMzMm8Js5TM75gk+lMB8GA1UdIwQYMBaAFJ0O6JA1
HmcmtGbnE1VBpuAj3/EjMA0GCSqGSIb3DQEBCwUAA4IBAQCh7v5ZoKQCqZ+Jfo+E
RXM8Yc0bLgwon0VuAsfVhACulRhEh+raloC4tC/+gaH2hhZo1cMsDH0sPw4/2ird
7pblFIRa10hQ5lRuz59+bO5OZwnZpXPYYCso9KfY5I5xoNDC1UC6T22ZwxLFiCxL
W7/IbRLN/BmMGYHwXg2H9LLeb/3n1UJDSNox9bHxM4OxjJw5mZwNg9qy5uSZYOd6
9e/zHl7dIq6MX618Wbk+oXCpi3RVaoJFeHlBrIdJK/hgbmaDJOgJ+lMEOrHWyjPg
LK2QDUoqRp31VeRk0UvBnwBQfgGYjvvb7qBWtPRwvGSsmhxxdaD4qUHi22athUAF
HqR9
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
// - user ca
// - user cert
// - user key
// - server ca
// - server cert
// - server key
// and the cleanup function to defer
func CreateAllCerts(t *testing.T) (string, string, string, string, string, string, func()) {
	cc, cleanupCC, err := DumpToTemp(clientCA)
	require.NoError(t, err)
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
	return cc, uc, uk, ca, sc, sk, func() {
		cleanupCC()
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
