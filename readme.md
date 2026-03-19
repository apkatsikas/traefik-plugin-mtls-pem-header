# mTLS PEM Header Plugin

A Traefik middleware plugin that sets custom headers from the HTTP request and client certificate (if provided) using `text/template`.

Extends the original [traefik-plugin-mtls-header](https://github.com/pnxs/traefik-plugin-mtls-header) with a `pemCert` template function that encodes the full client certificate as a properly formatted PEM block — including `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----` delimiters and 64-character line-wrapped base64 — suitable for forwarding to backends such as Keycloak that expect a standard PEM certificate in a header.

## Configuration

### Forward full PEM certificate (e.g. for Keycloak x509 auth)

The following configuration forwards the client certificate as a URL-encoded PEM block in the `ssl-client-cert` header, matching the format produced by nginx's `auth-tls-pass-certificate-to-upstream` annotation:

```yml
testData:
  headers:
    ssl-client-cert: '[[pemCert .Cert]]'
  encodeUrl: true
```

### Forward a specific certificate field

```yml
testData:
  headers:
    X-Client-CN: 'CN=[[.Cert.Subject.CommonName]]'
  encodeUrl: false
```

## Template Functions

| Function | Description |
|---|---|
| `pemCert .Cert` | Encodes the client certificate as a PEM block with delimiters and proper line wrapping |

All standard Go `text/template` built-in functions are also available. The template delimiters are `[[` and `]]`.

## Available Template Variables

| Variable | Type | Description |
|---|---|---|
| `.Cert` | `*x509.Certificate` | The client certificate presented during the TLS handshake. `nil` if no certificate was presented. |
| `.Request` | `*http.Request` | The incoming HTTP request |

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `headers` | `map[string]string` | required | Map of header name to template string |
| `encodeUrl` | `bool` | `false` | URL-encode the header value using path encoding (`%20` for spaces) |
