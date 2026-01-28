# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-27

### Added

- ESLint configuration with TypeScript support (flat config)
- Prettier configuration for consistent code formatting
- TypeScript strict mode with `tsconfig.json`
- `AGENTS.md` with coding guidelines for AI agents
- New npm scripts: `lint`, `lint:fix`, `format`, `format:check`, `typecheck`, `check`
- README badges for Cloudflare Workers, TypeScript, Workers AI, Prettier, ESLint
- `VERSION` file as single source of truth for versioning
- This `CHANGELOG.md` file
- Authentication for admin endpoints (`/populate`, `/refresh-docs`) via `ADMIN_SECRET`
- `ctx.waitUntil()` for background documentation refresh tasks

### Fixed

- ESLint errors (unused variables, unnecessary regex escapes)
- TypeScript type errors with Workers AI embedding response types
- XSS vulnerability in tunnel dropdown (escape HTML in user-controlled data)

### Changed

- Improved `.gitignore` with comprehensive ignore patterns
- Updated `compatibility_date` to `2026-01-27`

### Security

- Added `escapeHtml()` function to prevent XSS attacks from malicious tunnel names
- Admin endpoints now require `Authorization: Bearer <ADMIN_SECRET>` header
- Documented secure CORS defaults (same-origin only)

## [1.0.0] - 2026-01-14

### Added

- Initial release
- Template-based configuration generation for Magic WAN tunnels
- AI-powered configuration generation using Workers AI (Qwen 2.5 Coder)
- Vectorize integration for RAG-based documentation retrieval
- Troubleshooting chat assistant
- NAT-T support for devices behind NAT/CGNAT
- Scheduled documentation refresh (daily cron)
- Support for multiple device types:
  - Cisco IOS/IOS-XE
  - Cisco SD-WAN (Viptela)
  - Fortinet FortiGate
  - Palo Alto Networks
  - Juniper SRX
  - pfSense
  - Ubiquiti/VyOS
