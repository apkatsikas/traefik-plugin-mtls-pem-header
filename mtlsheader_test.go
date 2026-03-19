// Package traefik_plugin_mtls_header_test a test suit for custom header plugin
package traefik_plugin_mtls_header //nolint:revive,stylecheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const certPEM = `-----BEGIN CERTIFICATE-----
MIIDEDCCAfigAwIBAgIIQXxeH1vM+tYwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UE
AwwHdGVzdF9jYTAgFw0yMjEyMTYxNDQ1MDBaGA85OTk5MTIzMTIzNTk1OVowFjEU
MBIGA1UEAwwLbXRsc19jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDA4g7AcPxzOraD65UYakPOZ8c43E7yBZqcF85ZvfUrN5/eOItQUT2Kqw/M
x6ynfvliPHbqBaoCmuaJzigS5CJc4x3/nuYKKycqJaGXiQJ1i3hEQk+04TGdkTs0
4kzKkS1PNYOZCX11P/3hdQ4DykfxcfqKqvGLCCVGPbyr7C+hPzzIkppPJuMOM9oJ
Sb1AW3a+T2uOtI4J1wLq7IqlSyCzMVSzCI9CJ8vGIUe4RGlFR90ONHHYxz5EtkQq
lVM27o2zGqT4dPX5XMmAFdjeKIgS6SOAwSJjmLPvdKmvFkweeKqPPNwghjICokzb
0TVRorVYWSIGFXiNBQl1QLX2/A2FAgMBAAGjZDBiMAwGA1UdEwEB/wQCMAAwHQYD
VR0OBBYEFC0Po/+Vc34sMuYCOxVL7FOk4yg+MAsGA1UdDwQEAwIDuDATBgNVHSUE
DDAKBggrBgEFBQcDAjARBglghkgBhvhCAQEEBAMCBaAwDQYJKoZIhvcNAQELBQAD
ggEBADQHzmjRUsFaT8fiwt0QAh3uX18JVWiKGbC5YC6heBeqfq32TUmIqLDZl9lk
hnuI1+w0LTmn415bVz2xJsFmRXBMludH8MhQbkrL1hKSjrlEtF7K5pa3gt8lanEq
X2JPLSv2verLZr3ptJ6TI2RfbmdhRU5fEPETfPaf+2EkyZ8l6UbbUm7PV6XQsINX
GyxAcQq/xlonGAhWuAQ23nDP7TF8QmVAiY/C8TgidEvYmmWsna0ezOeDM/w7KX6+
zegYc03Fmul9vlGu9ZP70SNmyVFL//LIzXf16rvsMLNeWho5d8Y0usywXjuuS2WE
DqH21BZ19OniZNd5kW5xUaF7J0A=
-----END CERTIFICATE-----
`

func TestMtlsheader(t *testing.T) {
	cfg := CreateConfig()

	cfg.Headers["X-Host"] = "[[.Request.Host]]"
	cfg.Headers["X-Method"] = "[[.Request.Method]]"
	cfg.Headers["X-URL"] = "[[.Request.URL]]"
	cfg.Headers["X-Client-CN"] = "CN=[[.Cert.Subject.CommonName]]"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	clientBlock, _ := pem.Decode([]byte(certPEM))
	if clientBlock == nil {
		t.Fatal("failed to parse client certificate PEM")
	}
	clientCert, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		t.Fatal("failed to parse client certificate: " + err.Error())
	}

	certChain := []*x509.Certificate{clientCert}

	handler, err := New(ctx, next, cfg, "mTLS Header Plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.TLS = &tls.ConnectionState{
		PeerCertificates: certChain,
	}

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-Host", "localhost")
	assertHeader(t, req, "X-URL", "http://localhost")
	assertHeader(t, req, "X-Method", "GET")
	assertHeader(t, req, "X-Client-CN", "CN=mtls_client")
}

func TestSslClientCertHeader(t *testing.T) {
	cfg := CreateConfig()
	cfg.Headers["ssl-client-cert"] = "[[pemCert .Cert]]"
	cfg.EncodeURL = true

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	clientBlock, _ := pem.Decode([]byte(certPEM))
	if clientBlock == nil {
		t.Fatal("failed to parse client certificate PEM")
	}
	clientCert, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		t.Fatal("failed to parse client certificate: " + err.Error())
	}

	handler, err := New(ctx, next, cfg, "mTLS Header Plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	handler.ServeHTTP(recorder, req)

	raw := req.Header.Get("ssl-client-cert")
	if raw == "" {
		t.Fatal("ssl-client-cert header is missing")
	}

	// URL-decode the header value
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		t.Fatalf("failed to URL-decode ssl-client-cert header: %v", err)
	}

	// Verify PEM block delimiters are present
	if !strings.HasPrefix(decoded, "-----BEGIN CERTIFICATE-----\n") {
		t.Errorf("ssl-client-cert does not start with PEM header, got: %q", decoded[:60])
	}
	if !strings.HasSuffix(decoded, "-----END CERTIFICATE-----\n") {
		t.Errorf("ssl-client-cert does not end with PEM footer, got: %q", decoded[len(decoded)-60:])
	}

	// Verify the decoded PEM parses back to a valid certificate matching the original
	block, _ := pem.Decode([]byte(decoded))
	if block == nil {
		t.Fatal("failed to decode PEM block from ssl-client-cert header")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected PEM block type CERTIFICATE, got %q", block.Type)
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate from ssl-client-cert header: %v", err)
	}
	if parsed.Subject.CommonName != clientCert.Subject.CommonName {
		t.Errorf("common name mismatch: got %q, want %q", parsed.Subject.CommonName, clientCert.Subject.CommonName)
	}
	if !parsed.SerialNumber.IsInt64() || !clientCert.SerialNumber.IsInt64() || parsed.SerialNumber.Int64() != clientCert.SerialNumber.Int64() {
		if parsed.SerialNumber.Cmp(clientCert.SerialNumber) != 0 {
			t.Errorf("serial number mismatch: got %s, want %s", parsed.SerialNumber, clientCert.SerialNumber)
		}
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
