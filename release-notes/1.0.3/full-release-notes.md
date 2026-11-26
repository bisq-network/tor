# Tor Library 1.0.3 Release Notes

## Bundled Tor

The library uses the Tor Browser 16.0.3 Expert Bundle, which includes Tor 0.4.9.17. Tor 0.4.9.17 includes several security fixes, including stronger relay denial-of-service defenses for IPv6. [Tor Browser 16.0.3 release announcement](https://blog.torproject.org/new-release-tor-browser-1603/) [Tor 0.4.9.17 security release announcement](https://forum.torproject.org/t/security-release-0-4-9-17/22454)

The build ships Tor on Linux x86_64 and ARM64, macOS x86_64 and ARM64, and Windows x86_64. It verifies the Tor Project's signed SHA-256 manifest and checks both the hash and detached signature of the selected archive. [Tor Project Expert Bundle archive](https://archive.torproject.org/tor-package-archive/torbrowser/16.0.3/)

The bundle update requires no public API changes for Bisq 1 or Bisq 2.

## Build and repository changes since 1.0.2

- CI uses `actions/setup-java` 6.3.0, `gradle/actions/setup-gradle` 6.4.1 and CodeQL actions 4.39.3.
- New issues and pull requests receive guidance on contribution review and private security reporting. The build's workflow verifier recognizes the reviewed contribution notice. [Contribution guidelines](../../README.md) and [security reporting](../../SECURITY.md).
