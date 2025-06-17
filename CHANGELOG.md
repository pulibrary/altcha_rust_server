# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Dynamic domain cookie support for multi-domain deployments
- Enhanced logging with domain tracking
- OpenBSD rc.d service integration
- Complete project structure with CI/CD pipeline

### Changed
- Cookie domain is now determined dynamically from Host header
- Improved error handling and logging

### Fixed
- Cookie rejection issues for oar.princeton.edu domain
- ALTCHA widget integration and payload extraction

## [1.0.0] - 2025-06-17

### Added
- Initial implementation of ALTCHA proof-of-work server
- Challenge generation with SHA-256 hashing
- HMAC signature verification
- Verification cookie management
- Integration with nginx reverse proxy
- Comprehensive logging with client IP tracking
- Rate limiting and connection controls
- Structured JSON logging for nginx
- Cross-origin resource sharing (CORS) support
- Production-ready daemon script
- RESTful API with `/api/challenge` and `/api/verify` endpoints
- Embedded verification page with ALTCHA widget
- Production deployment scripts
- Comprehensive documentation
- CI/CD pipeline with GitHub Actions
- Security audit integration

### Security
- HMAC-SHA256 challenge signatures
- Secure cookie attributes (HttpOnly, Secure, SameSite=Strict)
- Client IP validation and logging
- Protection against replay attacks
- Initial security audit completed
- All dependencies verified for known vulnerabilities
