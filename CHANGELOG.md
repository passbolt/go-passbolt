# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

Releases before 0.8.2 are documented in the [GitHub releases](https://github.com/passbolt/go-passbolt/releases).

## [Unreleased]

## [0.8.4] - 2026-10-29
### Added
- PB-54610: Validate Resource metadata and secrets against the JSON schemas bundled with the SDK instead of the server definition
- PB-54610: Embed all Resource Type schemas as JSON files, including the six previously missing ones
- PB-54610: Validate leniently on read and strictly on write

### Fixed
- PB-54147: Harden the MFA retry loop and cover it with testing/synctest
- PB-56059: Fix the `FilterHasUsers` and `FilterHasGroup` filters
- PB-56059: Fix `FilterHasManagers` using only the last ID
- PB-56059: Fix `MissingMetadataKeyIDs` never being filled

### Security
- PB-54147: Move to the Go 1.26.8 and 1.27.1 security patches
- PB-55389: Update Go to 1.26.9 and 1.27.2 (security fixes in crypto/tls, net/http, net/textproto and os)
- PB-55610: Bump Go version to 1.26.10/1.27.3 (security fixes in crypto/x509)

### Maintenance
- PB-54147: Bump the toolchain to Go 1.27 and keep the SDK floor at 1.26.10
- PB-54147: Pin encoding/json v1 semantics across both implementations
- PB-54610: Cache compiled schemas per slug and section
- PB-54610: Add an integration test comparing the bundled schemas with the server
- PB-54610: Add scenario benchmarks
- PB-55287: Reorganize e2e test files in CLI and SDK
- PB-54998: Update GitHub Actions to stable versions
- PB-55888: Update Go dependencies
- PB-56059: Use `/setup/start` instead of the legacy `/setup/install` endpoint
- PB-56059: Add integration tests for the list filters

## [0.8.3] - 2026-08-27
### Fixed
- PB-53937: Sign shared v5 metadata with both the user key and the metadata key

## [0.8.2] - 2026-08-18
### Added
- PB-53915: Surface custom field functions in SDK

### Security
- PB-53335: Fix crypto/tls CVE-2026-42505 (Medium)
- PB-53334: Minor upgrade for golang.org/x/text (High)
- PB-53929: Minor upgrade for github.com/moby/go-archive (High)

### Maintenance
- PB-53919: Bump go version to 1.26.6
- PB-54017: Update dependencies in SDK and CLI
- PB-54022: Use go 1.25 syntax
- PB-53686: Document the minimum supported Passbolt API version
- PB-54031: Add changelog files to SDK and CLI
- PB-53914: Remove the community disclaimer from the README
- PB-53788: Update devcontainer version in go CI
- Renovate: Add renovate.json
- Adapt renovate config
