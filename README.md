# mic

mic (mina-is-cute) is a modular Golang proxy (HTTPS) to evade network JA4S fingerprinting.

It is planned to support HTTP / SOCKS5 in the future as well, but not within the first version.

## Compiling

You can simply run:

```bash
make
```

Or, you can also run this, to run with Docker:
```bash
make docker
```

## Usage

To know how to use it, simply run with `--help`

```bash
./mic --help
```

### Using self-signed certificates

You can generate certificates like so:

```bash
go run $(go env GOROOT)/src/crypto/tls/generate_cert.go --host="localhost,127.0.0.1"
```
