# sentinel-agent-modsec

ModSecurity WAF agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Provides full OWASP Core Rule Set (CRS) support via libmodsecurity.

> **Note:** This agent uses libmodsecurity bindings and requires the library to be installed on your system. For a lightweight, zero-dependency alternative with basic detection rules, see [sentinel-agent-waf](https://github.com/raskell-io/sentinel-agent-waf).

## Features

- **Full OWASP CRS support** - 800+ detection rules
- **SecLang compatibility** - Load any ModSecurity rules
- **Request body inspection** - JSON, form data, XML, and all content types
- **Response body inspection** - Detect data leakage (opt-in)
- **Block or detect-only mode** - Monitor before blocking
- **Path exclusions** - Skip inspection for trusted paths

## Prerequisites

### libmodsecurity

This agent requires libmodsecurity >= 3.0.13 installed on your system:

**macOS:**
```bash
brew install modsecurity
```

**Ubuntu/Debian:**
```bash
apt install libmodsecurity-dev
```

**From source:**
```bash
git clone https://github.com/owasp-modsecurity/ModSecurity
cd ModSecurity
git submodule init && git submodule update
./build.sh
./configure
make && make install
```

### OWASP Core Rule Set (CRS)

Download the OWASP CRS rules:

```bash
git clone https://github.com/coreruleset/coreruleset /etc/modsecurity/crs
cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
```

## Installation

### From crates.io

```bash
cargo install sentinel-agent-modsec
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-modsec
cd sentinel-agent-modsec
cargo build --release
```

## Usage

```bash
sentinel-modsec-agent \
  --socket /var/run/sentinel/modsec.sock \
  --rules /etc/modsecurity/crs/crs-setup.conf \
  --rules /etc/modsecurity/crs/rules/*.conf
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-modsec.sock` |
| `--rules` | `MODSEC_RULES` | Paths to rule files (comma-separated or multiple flags) | - |
| `--block-mode` | `MODSEC_BLOCK_MODE` | Block (true) or detect-only (false) | `true` |
| `--exclude-paths` | `MODSEC_EXCLUDE_PATHS` | Paths to exclude (comma-separated) | - |
| `--body-inspection` | `MODSEC_BODY_INSPECTION` | Enable request body inspection | `true` |
| `--max-body-size` | `MODSEC_MAX_BODY_SIZE` | Maximum body size to inspect (bytes) | `1048576` (1MB) |
| `--response-inspection` | `MODSEC_RESPONSE_INSPECTION` | Enable response body inspection | `false` |
| `--verbose` | `MODSEC_VERBOSE` | Enable debug logging | `false` |

## Configuration

### Sentinel Proxy Configuration

```kdl
agents {
    agent "modsec" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/modsec.sock"
        }
        events ["request_headers", "request_body_chunk", "response_body_chunk"]
        timeout-ms 100
        failure-mode "open"
    }
}

routes {
    route "all" {
        matches { path-prefix "/" }
        upstream "backend"
        agents ["modsec"]
    }
}
```

### Docker/Kubernetes

```yaml
# Environment variables
MODSEC_RULES: "/etc/modsecurity/crs/crs-setup.conf,/etc/modsecurity/crs/rules/*.conf"
MODSEC_BLOCK_MODE: "true"
MODSEC_EXCLUDE_PATHS: "/health,/metrics"
```

## Response Headers

On blocked requests:
- `X-WAF-Blocked: true`
- `X-WAF-Message: <modsecurity message>`

In detect-only mode, the request continues but includes:
- `X-WAF-Detected: <message>`

## OWASP CRS Paranoia Levels

The CRS supports paranoia levels 1-4. Configure in `crs-setup.conf`:

```
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"
```

| Level | Description |
|-------|-------------|
| 1 | Standard protection, minimal false positives |
| 2 | Elevated protection, some false positives |
| 3 | High protection, moderate false positives |
| 4 | Maximum protection, high false positives |

## Comparison with sentinel-agent-waf

| Feature | sentinel-agent-modsec | sentinel-agent-waf |
|---------|----------------------|-------------------|
| Detection Rules | 800+ CRS rules | ~20 regex rules |
| SecLang Support | ✓ | - |
| Custom Rules | ✓ | - |
| Body Inspection | ✓ | ✓ |
| Dependencies | libmodsecurity (C) | Pure Rust |
| Binary Size | ~50MB | ~5MB |
| Memory Usage | Higher | Lower |
| Installation | Requires libmodsecurity | `cargo install` |

**When to use this agent:**
- You need full OWASP CRS compatibility
- You have existing ModSecurity/SecLang rules
- You require comprehensive protection with 800+ detection rules

**When to use [sentinel-agent-waf](https://github.com/raskell-io/sentinel-agent-waf):**
- You want simple, zero-dependency deployment
- You need low latency and minimal resource usage
- Basic attack detection is sufficient

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --rules test-rules.conf

# Run tests
cargo test

# Check formatting and lints
cargo fmt --check
cargo clippy
```

## License

MIT OR Apache-2.0
