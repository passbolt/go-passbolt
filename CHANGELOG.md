# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

Releases before 0.8.2 are documented in the [GitHub releases](https://github.com/passbolt/go-passbolt/releases).

## [Unreleased]
### Fixed
- The TOTP MFA callback now reports how many attempts it actually made instead of always saying 3
- The TOTP MFA callback no longer waits one extra retry delay after its final failed attempt

### Maintenance
- PB-54147: Build and test with Go 1.27.1; the minimum supported Go version is now 1.26.8
- PB-54147: Use go 1.26 syntax

### Changed
- PB-54610: Validate Resource metadata and secrets against JSON schemas bundled with the SDK (lenient on read, strict on write) instead of the server-provided definitions, and bundle the six previously missing Resource Types. Resources of a type or with a field that a newer Passbolt release added cannot be read, updated or shared until the SDK is upgraded

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
