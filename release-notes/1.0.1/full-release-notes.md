# Tor Library 1.0.1 Release Notes

Proposed release notes for the first patch release of the Tor library. It updates the bundled Tor to Tor Browser 16.0.1 with tor 0.4.9.16, moves the sandbox to sandy 1.2.0 and fixes the sandboxed start on macOS when the Tor directory is reached through a symbolic link.

## Scope

These notes describe the changes from `v1.0.0` (`6edc00e7413a1a95767586abc4899a8f0202ac85`) to `main` at `48900d37` together with the update of the Tor bundle on branch `update-tor-to-v0.4.9.16`. `gradle.properties` declares version `1.0.1`. No release tag exists yet, so these are release-candidate notes, not a claim that version 1.0.1 has been published. Everything in the [1.0.0 release notes](../1.0.0/full-release-notes.md) that these notes do not change still applies.

## Integration Notes

- **Versioning:** 1.0.1 is a patch release. The public API is unchanged, and Bisq 1 and Bisq 2 need no code change.
- **Dependency verification of the applications:** Bisq 1 and Bisq 2 build the library as an included build and verify its dependencies with their own metadata. The sandy 1.2.0 archives of all five platforms must be added to the verification metadata and the checksum-only allowlist of both applications, and the entries of sandy 1.0.0 can be removed. The Tor bundle is not a Gradle dependency and needs no entry.
- **Windows AppContainer:** the AppContainer name is derived from the Tor directory. A user whose Tor directory lies behind a symbolic link or a junction now gets the real path, and therefore a new AppContainer, once.
- **Build JDK:** the build accepts every Azul build of Java 21 at or above `21.0.13.0.3`, instead of exactly 21.0.13. An application which builds the library must run Gradle on such a JDK.

## Notable Changes

### Embedded Tor

- The library installs and runs the Tor expert bundle of Tor Browser 16.0.1 with tor 0.4.9.16 (before: Tor Browser 16.0 with tor 0.4.9.15) on Linux x86_64, Linux ARM64, macOS x86_64, macOS arm64 and Windows x86_64.
- tor 0.4.9.16 is an emergency release for directory authorities: it reverts the required protocol versions which made clients up to 0.4.8 exit, and publishes a dummy TAP key in microdescriptors. For clients, such as the Tor of this library, it brings the fallback directories of 2026-11-04. Upstream changelog: <https://gitlab.torproject.org/tpo/core/tor/-/raw/release-0.4.9/ChangeLog>.
- The pluggable transport `lyrebird` moves from 0.9.0 to 0.10.0. `conjure-client` and the built-in bridges in `pt_config.json` are unchanged.
- The build pins the signed checksum file of Tor Browser 16.0.1 instead of that of 16.0. It is signed with subkey `022D A248 432D 2A0E 0F54 E65E 316C 1FAC D62D 07D9` of the pinned primary key `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`. The signing key which Tor publishes is unchanged, so the committed key was not refreshed.

### Sandbox

- The library runs the sandbox with sandy 1.2.0 instead of 1.0.0 and needs sandy 1.1.0 or newer. The policy templates keep their content: sandy 1.1.0 and 1.2.0 change nothing that the sandbox of Tor relies on, and the lines of the status record which the library reads are unchanged.
- Of sandy's warnings the library now shows only those which name the fallback level that Tor runs, or something on the host that can make Tor fail or weaken its sandbox: `session-zero`, `ecryptfs-unlisted`, `junction-closed`, `openssl-include`, `writable-home` and `writable-path-directory` (`Sandy.SHOWN_WARNING_IDS`). The other warnings, for example `egress-probing`, `view-partial` and `appcontainer-shared`, describe limits of a platform which the policy accepts and appeared on every start. A warning which a later sandy release adds stays hidden until it is reviewed.
- The build checks the sandy 1.2.0 archives against their pinned SHA-256 hashes and against the `SHA256SUMS` of the release, signed by the pinned sandy release key. Every archive of v1.2.0 was rebuilt from its tag byte for byte before the move.

### Fixes

- **macOS sandboxed start through a link:** a sandboxed Tor exited before it answered on its control port, with "Unable to open configuration file" for its torrc, when the application data directory was reached through a symbolic link, for example a link to the directory of the current version. `TorService` now resolves the links on the way to the Tor directory, so the torrc, the command line, the environment and the sandbox policy name only real paths. Links inside the Tor directory are not resolved. A directory which cannot be resolved is used as given, as before. An integration test starts Tor in the sandbox through a linked Tor directory.

### Build and CI

- `releaseBuild.javaVersion` is the minimum Java version (`21.0.13.0.3`), which removes the compromised emSign roots from `cacerts`. The toolchain resolver provides Zulu 21.0.13.0.3. CI installs the newest Azul build of Java 21 for each runner instead of a pinned build.
- A CodeQL workflow builds the code with the required JDK. Dependabot proposes updates of GitHub Actions after 7 days.
- First-time contributors are told that reviews of their pull requests are paused.

Details: [README.md](../../README.md), [the sandy binary](../../tor/src/main/resources/sandy/README.md), [Tor bundle verification](../../build-logic/tor-binary/README.md) and [dependency verification](../../gradle/README.md).

## Known Limitations

The limitations of the [1.0.0 release notes](../1.0.0/full-release-notes.md#known-limitations) still apply. The sandbox measurements in the README were taken with older Tor bundles; Tor Browser 16.0.1 and lyrebird 0.10.0 were not measured in the sandbox for these notes.

## Verification of These Notes

The notes were checked against the commits since `v1.0.0`, the README files and the upstream tor changelog. For the bundle update, the signed checksum file of Tor Browser 16.0.1 was verified with GnuPG against the key which Tor publishes, and on Linux ARM64 `verifyTorBinary`, `verifyTorBinaryVersion` (tor 0.4.9.16) and the tests of the `tor-binary` plugin passed. The Linux ARM64 bundles of 16.0 and 16.0.1 were compared file by file. The dependency verification metadata was regenerated from an empty Gradle user home and came out unchanged, and every key of the keyring is used. No integration test was run while writing these notes.
