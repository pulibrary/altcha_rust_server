# Deployment Guide

This guide covers deploying the ALTCHA Rust server to production.

## Prerequisites

- OpenBSD server (or other Unix-like system)
- Rust 1.70+
- nginx
- doas/sudo access

## Production Setup

### 1. Build and Install

```bash
# Clone the repository
git clone https://github.com/princeton-university/altcha-rust-server.git
cd altcha-rust-server

# Build release version
cargo build --release

# Install binary
doas cp target/release/altcha-server /usr/local/bin/
doas chmod +x /usr/local/bin/altcha-server
```

### 2. Install System Service

Choose one of the following methods:

#### Option A: OpenBSD rc.d Service (Recommended)

```bash
# Install rc.d script
doas cp scripts/altcha_rust.rc /etc/rc.d/altcha_rust
doas chmod +x /etc/rc.d/altcha_rust

# Enable and start the service
doas rcctl enable altcha_rust
doas rcctl start altcha_rust

# Check status
doas rcctl check altcha_rust
```

#### Option B: Manual Daemon Script

```bash
# Install daemon script
doas cp scripts/altcha-daemon.sh /usr/local/bin/
doas chmod +x /usr/local/bin/altcha-daemon.sh

# Create log directory
doas mkdir -p /var/log
doas touch /var/log/altcha-server.log
doas chown www:www /var/log/altcha-server.log
```

### 3. Security Configuration

⚠️ **Important**: Change the SECRET_KEY before production deployment!

Edit `src/main.rs` and change:
```rust
const SECRET_KEY: &str = "your-production-secret-key-here";
```

Generate a secure key:
```bash
openssl rand -hex 32
```

### 4. Start Services

```bash
# Start ALTCHA server (if using rc.d)
doas rcctl start altcha_rust

# OR start manually (if using daemon script)
doas /usr/local/bin/altcha-daemon.sh start

# Restart nginx
doas nginx -t  # Test configuration
doas nginx -s reload  # Reload if test passes
```

For complete deployment instructions, see the full documentation.
