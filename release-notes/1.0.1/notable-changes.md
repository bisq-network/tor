# Tor Library 1.0.1 Notable Changes

Changes from `v1.0.0` to `main` at `48900d37` together with the Tor bundle update on branch `update-tor-to-v0.4.9.16`. See the [full release notes](full-release-notes.md) for integration notes and limitations.

## Embedded Tor

- The library runs the Tor expert bundle of Tor Browser 16.0.1 with tor 0.4.9.16 (before: 16.0 with tor 0.4.9.15). The update brings new fallback directories for clients; its other fixes concern directory authorities.
- lyrebird moves from 0.9.0 to 0.10.0. conjure-client and the built-in bridges are unchanged.
- The build verifies each bundle against the signed checksums of Tor Browser 16.0.1.

## Sandbox

- The sandbox runs with sandy 1.2.0 instead of 1.0.0. The policy templates are unchanged.
- The library shows only the sandy warnings which name the fallback level or a host problem that can make Tor fail or weaken its sandbox. Warnings about accepted platform limits no longer appear on every start.

## Fixes

- On macOS, a sandboxed start no longer fails when the Tor directory is reached through a symbolic link. The library passes the real path of the Tor directory to Tor and to sandy.

## Build and CI

- The build accepts every Azul build of Java 21 at or above 21.0.13.0.3, and CI installs the newest Azul build of Java 21.
- A CodeQL workflow and Dependabot updates of GitHub Actions were added.

## Integration Requirements

- Bisq 1 and Bisq 2 must add the sandy 1.2.0 archives to their dependency verification metadata and checksum-only allowlist.
- On Windows, a Tor directory behind a link or junction gets a new AppContainer once.
