# IEEE 2030.5 Proxy

A high-performance proxy server for IEEE 2030.5 (Smart Energy Profile 2.0) communication, written in Zig. This proxy provides secure mTLS communication, connection pooling, and comprehensive logging for smart grid devices.

## Features

- **mTLS Support**: Full mutual TLS authentication with certificate validation
- **IEEE 2030.5 Compliance**: Supports standard message types (DER, metering, device control, etc.)
- **High Performance**: 
  - Zero-copy XML parsing
  - Connection pooling with DNS caching
  - Reference-counted async operations
  - Buffer pooling for memory efficiency
- **Certificate Management**:
  - LFDI/SFDI extraction
  - Hardware identity validation
  - Configurable vendor OID support
  - Session caching and resumption
- **Observability**:
  - Detailed request/response logging
  - XML message type identification
  - Performance metrics
  - Health check endpoints

## Requirements

- Zig master (latest development version)
- libuv
- OpenSSL 3.x
- libxml2 (optional, for full XML validation)

### macOS Installation

```bash
brew install libuv openssl@3 libxml2
```

### Linux Installation

```bash
# Ubuntu/Debian
apt-get install libuv1-dev libssl-dev libxml2-dev

# Fedora/RHEL
dnf install libuv-devel openssl-devel libxml2-devel
```

## Building

```bash
zig build
```

For release builds with optimizations:

```bash
zig build -Doptimize=ReleaseFast
```

## Configuration

Create a `server.toml` configuration file:

```toml
[server]
listen_addr = "0.0.0.0:8443"
health_addr = "127.0.0.1:8081"

[tls]
chain_path = "certs/server-chain.pem"
key_path = "certs/server.key"
root_ca_path = "certs/ca.pem"

[upstream]
backends = [
    "http://backend1:8080",
    "http://backend2:8080",
]

[logging]
level = "info"
format = "text"  # or "json"
detailed_logging = true
log_response_body = true
max_logged_body_size = 1048576

[health_check]
interval_seconds = 10
connection_timeout_ms = 1000

# Optional: Configure vendor-specific OIDs
[[vendors.vendor]]
name = "Acme Energy Systems"
oid = "1.3.6.1.4.1.12345"
device_type = "meter"

[[vendors.vendor]]
name = "Solar Innovations Inc"
oid = "1.3.6.1.4.1.54321"
device_type = "der_device"
```

### Vendor Configuration

The proxy supports configuring vendor-specific OIDs for device identification. Valid device types are:

- `der_device` - Distributed Energy Resource
- `meter` - Smart Meter
- `gateway` - Communication Gateway
- `aggregator` - DER Aggregator
- `ev_charger` - Electric Vehicle Charger
- `thermostat` - Smart Thermostat
- `custom` - Custom Device Type

## Running

```bash
./zig-out/bin/zig-proxy -c server.toml
```

## Certificate Requirements

The proxy expects IEEE 2030.5 compliant certificates with:

1. Standard IEEE 2030.5 policy OIDs:
   - Device: `1.3.6.1.4.1.40732.1.1`
   - Mobile: `1.3.6.1.4.1.40732.1.2`
   - Post-manufacture: `1.3.6.1.4.1.40732.1.3`
   - Test: `1.3.6.1.4.1.40732.2.1`
   - Self-signed: `1.3.6.1.4.1.40732.2.2`
   - Service provider: `1.3.6.1.4.1.40732.2.3`
   - Bulk issued: `1.3.6.1.4.1.40732.2.4`

2. Or configured vendor-specific OIDs

3. Hardware identity in certificate extensions or subject DN

## Architecture

The proxy uses:
- **libuv** for async I/O and event loop
- **OpenSSL** for TLS and cryptography
- **Zero-copy parsing** for performance
- **Arena allocators** for request-scoped memory
- **Reference counting** for safe async operations
- **Connection pooling** for upstream efficiency

## Message Types Supported

- DER (Distributed Energy Resource) messages
- Device capability and status
- Metering and usage data
- Demand response programs
- Tariff and pricing information
- Event and log messages
- File transfer
- Subscription and notification

## Performance Tuning

The proxy includes several performance optimizations:

- Session cache: 20,000 entries with 1-hour timeout
- Connection pool: 300-3000 connections per upstream
- Buffer pool: Pre-allocated 8KB buffers
- Backpressure: Automatic request throttling
- Keep-alive: Connection reuse for efficiency

## Health Monitoring

Health check endpoint: `http://health_addr/health`

Returns:
- Active connections
- Request rate
- Pool statistics
- Memory usage

## Development

### Project Structure

```
src/
├── main.zig              # Entry point
├── proxy.zig             # Main proxy server
├── connection.zig        # Connection handling
├── upstream.zig          # Upstream communication
├── connection_pool.zig   # Connection pooling
├── mtls/                 # mTLS implementation
│   ├── tls.zig          # TLS server
│   ├── certificate.zig   # Certificate handling
│   └── validation.zig    # Certificate validation
├── utils/                # Utilities
│   ├── uv.zig           # libuv bindings
│   ├── openssl.zig      # OpenSSL bindings
│   └── refcounted.zig   # Reference counting
└── xml_parser.zig        # XML parsing
```

### Testing

Run tests with:

```bash
zig build test
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

[Choose your license - e.g., MIT, Apache 2.0, etc.]

## Acknowledgments

This proxy was designed for IEEE 2030.5 (SEP2) compliance in smart grid deployments. It provides the secure communication infrastructure needed for distributed energy resources, smart meters, and grid management systems.
