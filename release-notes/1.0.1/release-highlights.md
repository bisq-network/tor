# Tor Library 1.0.1 Highlights

## Tor 0.4.9.16

The library now runs the Tor expert bundle of Tor Browser 16.0.1 with tor 0.4.9.16 and lyrebird 0.10.0. As before, the build checks every bundle against the signed checksums of the Tor Browser release.

## sandy 1.2.0

The sandbox moves to sandy 1.2.0 with unchanged policies. The library now shows only the sandbox warnings that matter on the host, instead of the same platform notes on every start.

## Sandboxed Start on macOS

A sandboxed Tor now starts on macOS also when the application data directory is reached through a symbolic link.

See [notable changes](notable-changes.md) and [full release notes](full-release-notes.md) for details.
