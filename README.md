# ALTCHA Rust Server

A high-performance, self-hosted ALTCHA (proof-of-work CAPTCHA) server implementation in Rust, designed for Princeton University's dataspace and OAR services.

## Features

- 🚀 **High Performance**: Built with Axum for blazing-fast request handling
- 🔒 **Secure**: HMAC signature verification and proof-of-work validation
- 🛡️ **Bot Protection**: Integrated with nginx for seamless bot filtering
- 🍪 **Cookie-based Sessions**: 24-hour verification cookies
- 📊 **Comprehensive Logging**: Structured logging with client IP tracking
- 🔧 **Production Ready**: Designed for high-traffic university services

## Quick Start

### Prerequisites

- Rust 1.70+
- Tested on OpenBSD (but should work with any Unix-like system)
- nginx (for reverse proxy)

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/pulibrary/altcha_rust_server.git
cd altcha_rust_server
```

2. **Build the server:**

```bash
cargo build --release
```

3. **Install the binary:**

```bash
doas cp target/release/altcha-server /usr/local/bin/
```

4. **Install system service (choose one):**

**Option A: OpenBSD rc.d service (recommended):**

```bash
doas cp scripts/altcha_rust.rc /etc/rc.d/altcha_rust
doas chmod +x /etc/rc.d/altcha_rust
doas rcctl enable altcha_rust
doas rcctl start altcha_rust
```

**Option B: Manual daemon script:**

```bash
doas cp scripts/altcha-daemon.sh /usr/local/bin/
doas chmod +x /usr/local/bin/altcha-daemon.sh
doas /usr/local/bin/altcha-daemon.sh start
```

### Configuration

The server runs on `127.0.0.1:8080` by default and is designed to work behind an nginx reverse proxy.

Key configuration constants in `src/main.rs`:

- `SECRET_KEY`: HMAC signing key (change in production!)
- `MAX_NUMBER`: Maximum number for proof-of-work (default: 50,000)
- `COOKIE_NAME`: Name of the verification cookie

## API Endpoints

### `GET /api/challenge`

Returns a new ALTCHA challenge.

**Response:**

```json
{
  "algorithm": "SHA-256",
  "challenge": "5229809ae4b9afeac7a3bc636fefa8cccc4656184bb319760f358cdbe19631fa",
  "maxnumber": 50000,
  "salt": "56dbac600bcc80a41b8c34e38f7e6641",
  "signature": "7d208b9b2657ccf44515d1c7fb80133585d9ac1f19ed9264d4e73d3ce3a97821"
}
```

### `POST /api/verify`

Verifies an ALTCHA solution.

**Request:**

```json
{
  "altcha": "eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY2hhbGxlbmdlIjoiNTIyOTgwOWFlNGI5YWZlYWM3YTNiYzYzNmZlZmE4Y2NjYzQ2NTYxODRiYjMxOTc2MGYzNThjZGJlMTk2MzFmYSIsIm51bWJlciI6MTIzNDUsInNhbHQiOiI1NmRiYWM2MDBiY2M4MGE0MWI4YzM0ZTM4ZjdlNjY0MSIsInNpZ25hdHVyZSI6IjdkMjA4YjliMjY1N2NjZjQ0NTE1ZDFjN2ZiODAxMzM1ODVkOWFjMWYxOWVkOTI2NGQ0ZTczZDNjZTNhOTc4MjEifQ=="
}
```

**Success Response:**

```json
{
  "status": "verified",
  "message": "Verification successful"
}
```

### `GET /`

Serves the verification challenge page with embedded ALTCHA widget.

## How It Works

1. **Challenge Generation**: Server creates a secret number and generates SHA-256 hash
2. **Client Solving**: ALTCHA widget iterates through numbers to find one that produces the challenge hash
3. **Verification**: Server validates the solution and signature
4. **Cookie Setting**: On success, sets a 24-hour verification cookie for the specific domain

## Nginx Integration

The server is designed to work with nginx for production deployment. See the included nginx configuration in `docs/nginx.conf`.

Key nginx features:

- Rate limiting (30 requests/minute)
- Connection limits (15 per IP)
- Automatic redirect to verification page for unverified users
- Proxy headers for real client IP detection

## Development

### Running in Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy lints
cargo clippy -- -D warnings
```

### Project Structure

```
├── src/
│   └── main.rs              # Main application code
├── scripts/
│   ├── altcha_rust.rc       # OpenBSD rc.d script
│   └── altcha-daemon.sh     # Manual daemon script
├── docs/
│   ├── nginx.conf           # Example nginx configuration
│   └── DEPLOYMENT.md        # Deployment instructions
├── Cargo.toml               # Rust dependencies
└── README.md                # This file
```

## Security Considerations

⚠️ **Important**: Change the `SECRET_KEY` in production! The current key is for development only.

- Uses HMAC-SHA256 for challenge signatures
- Validates proof-of-work solutions cryptographically
- Rate limiting and connection limits via nginx
- Secure cookie attributes (HttpOnly, Secure, SameSite=Strict)
- Dynamic domain-specific cookies for multi-domain support

## Production Deployment

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed production setup instructions.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`cargo test && cargo clippy`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Standards

- Follow Rust standard formatting (`cargo fmt`)
- All code must pass clippy lints (`cargo clippy`)
- Include tests for new functionality
- Update documentation for API changes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions:

- Create an issue in this repository
- Contact the Princeton University IT team

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.
