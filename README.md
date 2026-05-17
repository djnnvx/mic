# mic

mic (mina-is-cute) is a modular Go proxy for controlling outbound TLS fingerprints.
It lets you pick a browser fingerprint profile and the proxy will use the corresponding
[`bogdanfinn/utls`](https://github.com/bogdanfinn/utls) preset when connecting to upstream
servers, making your traffic look like a specific browser to any fingerprinting system.

Two modes are supported:

- **client-front**: HTTP CONNECT proxy with optional MitM TLS interception. The proxy
  generates a local CA, issues per-host leaf certs on the fly, terminates TLS from
  the client, and re-dials the target with the configured uTLS fingerprint. Standard
  tools (curl, browsers) work after importing the CA once.
- **server-front**: the proxy terminates incoming TLS (with your own cert/key), then
  re-dials the backend with the configured fingerprint. Useful when the client cannot
  be configured to use a CONNECT proxy.

---

## How it works

```mermaid
sequenceDiagram
    participant C as Client
    participant P as mic proxy
    participant T as Target

    rect rgb(30, 30, 60)
        note over C,T: client-front mode (MitM TLS)
        C->>P: HTTP CONNECT target:443
        P->>T: TCP + uTLS handshake (configured fingerprint)
        note right of P: JA4 = configured profile
        P-->>C: 200 Connection Established
        C->>P: TLS handshake (mic-issued cert for target)
        P-->>C: TLS established
        note left of P: JA4S = stdlib crypto/tls (measured only)
        C->>P: HTTP request (decrypted by proxy)
        P->>T: request bytes (through uTLS tunnel)
        T-->>P: HTTP response (through uTLS)
        P-->>C: HTTP response (re-encrypted for client)
    end

    rect rgb(30, 60, 30)
        note over C,T: server-front mode
        C->>P: TLS handshake (proxy cert)
        P-->>C: TLS established
        note left of P: JA4S = stdlib crypto/tls (measured only)
        P->>T: TCP + uTLS handshake (configured fingerprint)
        note right of P: JA4 = configured profile
        C->>P: HTTP request (decrypted by proxy)
        P->>T: request bytes (through uTLS tunnel)
        T-->>P: HTTP response (through uTLS)
        P-->>C: HTTP response (re-encrypted for client)
    end
```

In both modes the target sees a TLS handshake that matches the configured fingerprint
(JA4), not the default Go TLS fingerprint. The ServerHello mic returns to the client
(JA4S) is currently emitted by stdlib `crypto/tls` and is only measured, not yet
spoofed. See the JA4S section below for details.

---

## Build

```bash
go build -o mic .
```

---

## Running

### client-front

```bash
mic client --listen :8080 --fingerprint chrome-120 \
           --intercept-cert ca.pem --intercept-key ca-key.pem
```

`--intercept-cert` and `--intercept-key` enable MitM interception. mic generates the
CA files on first run and reuses them. Import the cert once, then all traffic through
the proxy is transparently intercepted and re-dialled with the configured fingerprint.

**Trust the CA** (pick whichever applies):

```bash
# curl: pass on every call, or set CURL_CA_BUNDLE
curl --cacert ca.pem -x http://localhost:8080 https://tlsinfo.me/json

# Debian / Ubuntu / Kali
sudo cp ca.pem /usr/local/share/ca-certificates/mic-ca.crt && sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem
```

After trusting, standard tools work without extra flags:

```bash
curl -x http://localhost:8080 https://tlsinfo.me/json
# check the "ja4" field. It should match the fingerprint you configured.
```

Omit `--intercept-*` to run as a plain CONNECT proxy (no MitM, raw tunnel only).

### server-front

Generate a cert for the proxy to present to clients:

```bash
go run $(go env GOROOT)/src/crypto/tls/generate_cert.go --host="localhost,127.0.0.1"
# produces cert.pem and key.pem
```

```bash
mic server --listen :8080 --backend 10.0.0.1:443 \
           --cert cert.pem --key key.pem \
           --fingerprint chrome-120
```

`--backend`, `--cert`, and `--key` are required. `--fingerprint` is optional; without
it the proxy falls back to a randomised uTLS preset.

### Available fingerprint profiles

Hashes are measured by `cmd/probe` against tlsinfo.me and reflect what each utls
preset actually emits. Re-run the probe after upgrading the utls dependency.

| Profile | JA4 hash |
|---|---|
| `chrome-120` | `t13d1516h2_8daaf6152771_02713d6af862` |
| `chrome-120-pq` | same as `chrome-120`¹ |
| `chrome-131` | same as `chrome-120`¹ |
| `chrome-133` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| `firefox-120` | `t13d1715h2_5b57614c22b0_5c2c66f702b0` |
| `safari-16` | `t13d2014h2_a09f3c656075_14788d8d241b` |
| `ios-16` | same as `safari-16`² |
| `edge-85` | `t13d1515h2_8daaf6152771_de4a06bb82e3` |
| `edge-106` | `t13d1516h2_8daaf6152771_e5627efa2ab1` |
| `opera-91` | same as `edge-106`³ |
| `android-11-okhttp` | `t12d120700_d34a8e72043a_036209cd1ead` (TLS 1.2) |

> ¹ `chrome-120-pq` and `chrome-131` produce the same JA4 as `chrome-120` because JA4
> does not distinguish key share entries. Use `chrome-120-pq` when you specifically need
> the X25519MLKEM768 post-quantum key exchange; use `chrome-131` for the most current
> non-PQ Chrome preset under this hash.
>
> ² `ios-16` collides with `safari-16` under JA4 (both ship the same TLS stack).
> Pick whichever matches the user-agent you intend to imitate.
>
> ³ `opera-91` collides with `edge-106` (both are Chromium derivatives with matching
> ClientHello shape). Same logic as above.

---

## Testing

```bash
# unit tests
go test ./...

# integration tests: spin up in-process TLS servers, no network required
go test -tags integration -v ./proxy/... ./fingerprint/...
```

The integration suite includes JA4 fingerprint verification tests: for each profile,
both `TestClientFront_JA4` and `TestServerFront_JA4` capture the raw ClientHello sent
by the proxy's uTLS engine and assert the computed JA4 hash matches the expected value.
This is the offline equivalent of running `cmd/probe` against tlsinfo.me.

CI runs both suites on every push via `.github/workflows/ci.yml`.

---

## JA4S (server-side fingerprint, measurement only)

mic also computes JA4S, the fingerprint of the ServerHello it emits to clients.
This is currently **measurement only**: there is no spoofing engine. The
integration tests `TestServerFront_JA4S_Baseline` and `TestClientFront_JA4S_Baseline`
capture the bytes mic writes during the TLS handshake and assert the JA4S matches
a recorded baseline.

The baseline is what stdlib `crypto/tls.Server` emits today: `t130200_1301_a56c5b993250`
(TLS 1.3, no ALPN, `TLS_AES_128_GCM_SHA256`, default extension set). It applies to
both modes because both terminate TLS with the same stdlib server.

Why no spoofing yet:

- `bogdanfinn/utls` does not expose server-side fingerprint control. Its `Server()`
  delegates to stdlib's TLS state machine.
- TLS 1.3 ServerHello carries only 2-3 extensions, so the JA4S surface is much
  smaller than JA4.

Spoofing would require either forking utls to add a `ServerHelloSpec`, or writing a
custom TLS server. The measurement code is in place so we can see if that effort is
worth it once we have real-world JA4S targets.
