go-passbolt v0.8.4 validates Resources against JSON schemas bundled with the SDK instead of the definitions served by the Passbolt API. This release also fixes the group and user filters and the TOTP MFA retry loop. It moves to the latest Go security patches.

## Bundled Resource Type schemas
Resource metadata and secrets were validated against the schema definitions the server returned, so the result depended on which server the SDK talked to. The SDK now embeds the schemas of every Resource Type, including six that were previously missing, and validates against those.

Validation is lenient on read and strict on write. A Resource carrying a field this build does not declare can still be read, but anything the SDK creates, updates or shares must match the schema, so that Resource cannot be updated or shared until the SDK is upgraded. A Resource whose type was added by a newer Passbolt release cannot be read at all until then.

## MFA fixes
When TOTP verification failed, the callback always reported 3 attempts, however many it had actually made, and waited one extra retry delay after the final attempt. It now reports the real number of attempts and returns as soon as the last one fails.

## List filter fixes
`FilterHasUsers` and `FilterHasGroup` had no effect. They returned all groups or users. `FilterHasManagers` only used the last ID. `MissingMetadataKeyIDs` was never filled. These now work as expected.

## Go version and dependencies
The SDK is built and tested with Go 1.27.3 and now requires Go 1.26.10 or later. This picks up the Go security fixes in crypto/tls, net/http, net/textproto, os and crypto/x509. Dependencies are updated, including gopenpgp v3.5.2.

## Conclusion
Many thanks to everyone who provided feedback, reported bugs, and contributed to making Passbolt better!

## Changelogs
### Added
- PB-54610 Validate Resource metadata and secrets against the JSON schemas bundled with the SDK instead of the server definition
- PB-54610 Embed all Resource Type schemas as JSON files, including the six previously missing ones
- PB-54610 Validate leniently on read and strictly on write

### Fixed
- PB-54147 Harden the MFA retry loop and cover it with testing/synctest
- PB-56059 Fix the `FilterHasUsers` and `FilterHasGroup` filters
- PB-56059 Fix `FilterHasManagers` using only the last ID
- PB-56059 Fix `MissingMetadataKeyIDs` never being filled

### Security
- PB-54147 Move to the Go 1.26.8 and 1.27.1 security patches
- PB-55389 Update Go to 1.26.9 and 1.27.2 (security fixes in crypto/tls, net/http, net/textproto and os)
- PB-55610 Bump Go version to 1.26.10/1.27.3 (security fixes in crypto/x509)

### Maintenance
- PB-54147 Bump the toolchain to Go 1.27 and keep the SDK floor at 1.26.10
- PB-54147 Pin encoding/json v1 semantics across both implementations
- PB-54610 Cache compiled schemas per slug and section
- PB-54610 Add an integration test comparing the bundled schemas with the server
- PB-54610 Add scenario benchmarks
- PB-55287 Reorganize e2e test files in CLI and SDK
- PB-54998 Update GitHub Actions to stable versions
- PB-55888 Update Go dependencies
- PB-56059 Use `/setup/start` instead of the legacy `/setup/install` endpoint
- PB-56059 Add integration tests for the list filters
