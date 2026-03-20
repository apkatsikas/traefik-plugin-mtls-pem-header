// Package traefik_plugin_mtls_pem_header a custom header plugin
package traefik_plugin_mtls_pem_header //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"text/template"
)

// Config the plugin configuration.
type Config struct {
	Headers   map[string]string `json:"headers,omitempty"`
	EncodeURL bool
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers:   make(map[string]string),
		EncodeURL: false,
	}
}

// MtlsHeader a MtlsHeader plugin.
type MtlsHeader struct {
	next      http.Handler
	headers   map[string]string
	encodeURL bool
	name      string
	template  *template.Template
}

// certToPEM encodes an x509 certificate to a PEM-formatted string including
// the BEGIN/END delimiters and proper 64-character line-wrapped base64 body.
// Returns an empty string if cert is nil.
func certToPEM(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// New created a new MtlsHeader plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	funcMap := template.FuncMap{
		"pemCert": certToPEM,
	}

	return &MtlsHeader{
		headers:   config.Headers,
		encodeURL: config.EncodeURL,
		next:      next,
		name:      name,
		template:  template.New("mtlsheader").Delims("[[", "]]").Funcs(funcMap),
	}, nil
}

type data struct {
	Request *http.Request
	Cert    *x509.Certificate
}

func (a *MtlsHeader) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	d := data{
		Request: req,
		Cert:    nil,
	}

	// load certificate
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		for _, cert := range req.TLS.PeerCertificates {
			d.Cert = cert
			break
		}
	}

	for key, value := range a.headers {
		tmpl, err := a.template.Parse(value)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		writer := &bytes.Buffer{}

		err = tmpl.Execute(writer, d)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if a.encodeURL {
			req.Header.Set(key, url.PathEscape(writer.String()))
		} else {
			req.Header.Set(key, writer.String())
		}
	}

	a.next.ServeHTTP(rw, req)
}
