# Gradle Notes

## Build JDK

`gradle.properties` pins the Java update (`releaseBuild.javaVersion`) and the vendor (`releaseBuild.javaVendor`) of the
JDK which runs Gradle, the same for every operating system. `verifyBuildEnvironment` (part of `check`) accepts every
build of that update: the version numbers of the JDK must start with those of the pin, so `21.0.13.0.3+1` passes for
`21.0.13`, and `21.0.13` fails for `21.0.1`. The pin holds version numbers only; `21` alone would accept every update
of Java 21. The task logs the runtime version and the Zulu build of the JDK.

Azul builds an update more than once, and an installer may offer only the latest build: Zulu `21.54.107`
(`21.0.13+9`) and `21.54.109` (`21.0.13.0.3+1`) are both builds of 21.0.13, and the Homebrew cask `zulu@21` has only
the latest. The two differ in their runtime (21.54.109 removes the emSign roots from `cacerts`), which this build does
not ship, but not in what it compiles with: their javac and the classes it compiles against differ only in version
strings.

`releaseBuild.javaRuntimeVersion` is the one build which the CI workflows install. setup-java looks it up for the
platform of each runner, so no build is listed per platform. `verifyGithubActionsSecurity` requires every `java-version`
of a workflow to be this build, and this build to be one of `releaseBuild.javaVersion`.

Update the workflows, the pinned properties, and the toolchain URLs in `build-logic/toolchain-resolver` together when
changing the Java update.

## Gradle Wrapper Verification

`verifyGradleWrapperSecurity` (part of the root `check`) and the CI workflow compare `gradlew`, `gradlew.bat`,
`gradle/wrapper/gradle-wrapper.jar` and `gradle/wrapper/gradle-wrapper.properties` with the approved checksums in
`gradle/wrapper/gradle-wrapper.sha256`. The task also requires `distributionUrl` to point to `services.gradle.org` for
`releaseBuild.gradleVersion` with a pinned `distributionSha256Sum`.

These checksums are written by this repository, so a change which replaces the wrapper jar can replace its checksum as
well. CI therefore also checks the jar against the checksums which Gradle publishes (`validate-wrappers: true` of
`gradle/actions/setup-gradle`), and `verifyGithubActionsSecurity` requires that setting.

The checksums cover the committed bytes. `.gitattributes` disables line-ending conversion for `gradlew.bat` (`-text`),
which is committed with CRLF line endings as Gradle generates it; the other files are committed with LF. Do not
renormalize these files.

After a reviewed wrapper change, for example `./gradlew wrapper --gradle-version <version>`, recompute and review the
checksums and update `gradle/wrapper/gradle-wrapper.sha256`, `distributionSha256Sum` and `releaseBuild.gradleVersion`
in the same change:

```bash
sha256sum gradlew gradlew.bat gradle/wrapper/gradle-wrapper.jar gradle/wrapper/gradle-wrapper.properties
```

A checksum mismatch means the working copy differs from the approved bytes. Review the difference; do not update the
checksum file to match an unreviewed file.

## Dependency Verification

The build uses Gradle dependency verification with:

- `verify-metadata`
- `verify-signatures`
- armored keyring format
- key servers off (`<key-servers enabled="false"/>`)

With the key servers off, a build verifies the signatures with the keys of `gradle/verification-keyring.keys` alone and
downloads no key. If the keyring lacks a key, every artifact which that key signed fails the verification, so a build
which passes, also on a CI runner with an empty Gradle user home, shows that the committed keyring has every key the
build needs. Gradle still asks the key servers for missing keys when it writes the metadata or exports the keyring
(`--write-verification-metadata`, `--export-keys`, and `refreshDependencyVerificationKeyring`), unless `--offline` is
given. Review the keys which these commands add before committing them. Gradle leaves the `<key-servers>` line out
when it writes the metadata with the key servers on; `verifyDependencySignaturePolicy` fails until
`<key-servers enabled="false"/>` is back after `<keyring-format>`.

The committed verification files are:

- `gradle/verification-metadata.xml`
- `gradle/verification-keyring.keys`
- `gradle/dependency-checksum-fallback-allowlist.tsv`

The root `resolveAndVerifyDependencies` task resolves every resolvable configuration of the root build and the
`build-logic` included build.

Gradle verifies an artifact when it resolves it, and a reused configuration cache entry would skip the resolution. The
tasks which resolve every configuration, and `verifyDependencySignaturePolicy` and `dependencySignatureReport`, which
always run with them, are therefore declared incompatible with the configuration cache: with `--configuration-cache`
Gradle runs them, but stores no entry for such an invocation. The other checks of `build` work with the configuration
cache.

Gradle reads the verification metadata only from `gradle/` of the root of the build tree, so `build-logic` is verified
only as part of this build. A build of `build-logic` on its own (`-p build-logic`) fails; run its tasks from the
repository root instead, for example `./gradlew :build-logic:gradle-tasks:test`.

Each build keeps its own `.gradle/dependency-verification/inventory.tsv` relative to its build root. These inventories
survive `clean`. Unchanged inventories are `UP-TO-DATE`; they are regenerated when resolved modules, direct dependency
scopes, artifact names or contents, verification metadata, or keyring change, or when an inventory is removed or
modified. Java source changes alone do not invalidate them.

Gradle still resolves and verifies dependencies when evaluating the inventory inputs, so graph changes from properties,
resolution rules, dynamic versions, and local repositories stay visible. The signature policy remains part of `check`
and is checked on each invocation. `--refresh-dependencies`, `--write-verification-metadata`, and `--rerun-tasks` force
inventory generation. The audit fails when the verification mode is `off` or `lenient`, whether set with
`--dependency-verification` or the `org.gradle.dependency.verification` property (for example in
`~/.gradle/gradle.properties`), because Gradle would not verify artifacts in those modes.

### Verifying build dependencies

To verify the current metadata without rewriting it:

```bash
./gradlew resolveAndVerifyDependencies
./gradlew verifyDependencySignaturePolicy
```

`./gradlew dependencySignatureReport` writes `docs/dependency-signature-report.md`. CI writes it again and fails if it
differs from the committed report, so regenerate it with every change of the dependencies or of the verification files.

### Adding or updating a dependency

```bash
./gradlew resolveAndVerifyDependencies --write-verification-metadata pgp,sha256
./gradlew verifyDependencySignaturePolicy
./gradlew dependencySignatureReport
```

`--write-verification-metadata` only adds entries for the artifacts resolved in this run. It never removes entries,
trusted keys, ignored keys or checksum-fallback reasons that the build no longer uses. With a warm Gradle user home it
can also miss artifacts that a fresh CI run requests, for example `kotlinx-coroutines-bom`, which is reached only
through Gradle module metadata. To catch them, run the command with an empty Gradle user home (see below).

### Regenerating the metadata from scratch

Use this to drop stale entries, for example after removing or upgrading dependencies.

1. Reduce `gradle/verification-metadata.xml` to its configuration and keep only the entries Gradle cannot regenerate
   (see [IDE import](#ide-import)) and the trusted keys narrowed by hand (see
   [Trusted keys narrowed by hand](#trusted-keys-narrowed-by-hand)):

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <verification-metadata xmlns="https://schema.gradle.org/dependency-verification" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://schema.gradle.org/dependency-verification https://schema.gradle.org/dependency-verification/dependency-verification-1.3.xsd">
      <configuration>
         <verify-metadata>true</verify-metadata>
         <verify-signatures>true</verify-signatures>
         <keyring-format>armored</keyring-format>
         <key-servers enabled="false"/>
         <trusted-keys>
            <!-- keep the manually maintained trusted keys here -->
         </trusted-keys>
      </configuration>
      <components/>
   </verification-metadata>
   ```

2. Regenerate the metadata and export the keyring with an empty Gradle user home. Copy the wrapper distribution to
   avoid downloading it again:

   ```bash
   export GRADLE_USER_HOME=$(mktemp -d)
   mkdir -p "$GRADLE_USER_HOME/wrapper/dists"
   cp -a ~/.gradle/wrapper/dists/gradle-<version>-bin "$GRADLE_USER_HOME/wrapper/dists/"
   ./gradlew --no-daemon --no-build-cache resolveAndVerifyDependencies \
     --write-verification-metadata pgp,sha256 --export-keys
   unset GRADLE_USER_HOME
   ```

   `--export-keys` writes the keys which the new metadata uses, but keeps the keys which are already in
   `gradle/verification-keyring.keys`. Do not delete the keyring before this step: Gradle's signing key
   (`E2F38302C8075E3D`, used for `gradle-kotlin-dsl-plugins`) is not published on any key server, so it is available
   only from the committed keyring. To drop unused keys, first reduce the keyring to the `pub` blocks of the keys that
   the new metadata references.

3. Remove allowlist entries which are no longer checksum-only, then run the policy and the report:

   ```bash
   ./gradlew verifyDependencySignaturePolicy
   ./gradlew dependencySignatureReport
   ```

Review the generated diff and verify new signatures or checksums before committing. Metadata generation records
downloaded artifacts; it does not independently establish their trustworthiness.

### Trusted keys narrowed by hand

A regeneration trusts a key which signs several artifacts of a group for the whole group, so the entry also accepts any
future artifact of the group which that key signs. These entries are narrowed by hand and must be kept through a
regeneration:

- Key `D477D51812E692011DB11E66A6EA2E2BF22E0543`, which has no user ID in the keyring, is trusted only for
  `io.github.java-diff-utils:java-diff-utils:4.12` and its parent POM `java-diff-utils-parent:4.12`, the two artifacts
  of the group which the build resolves. Update the version when the build resolves another one.

### Keyring

```bash
./gradlew refreshDependencyVerificationKeyring
```

refreshes the keys from the key servers and exports the armored keyring to `gradle/verification-keyring.keys`. It wraps
`./gradlew help --refresh-keys --export-keys`. Like `--export-keys` above, it never removes a key from the keyring.
The binary keyring `gradle/verification-keyring.gpg` is not used.

Some Gradle/Bouncy Castle combinations may write the armored keyring and then fail while finishing key export. The
wrapper task accepts that case only if `gradle/verification-keyring.keys` was updated.

Run it before `--write-verification-metadata` when signing keys may have changed, so newly available keys are present
before Gradle rewrites `gradle/verification-metadata.xml`. This avoids adding checksum fallbacks for artifacts whose
signatures can now be verified.

### IDE import

IDE import can resolve artifacts that `resolveAndVerifyDependencies` does not request: `-sources.jar` and
`-javadoc.jar` archives, and the sources of the Groovy modules that Gradle embeds. `--write-verification-metadata`
records only what the run requests, so these entries are maintained by hand:

- The `org.apache.groovy` modules of version 4.0.27 (embedded in Gradle 9.0.0) are trusted for key
  `34441E504A937F43EB0DAEF96A65176A0FB1CD0B`. Update the version when Gradle upgrades its embedded Groovy.
- The Gradle sources `gradle:gradle:9.0.0` (`gradle-9.0.0-src.zip`, which the IDE fetches from the Gradle
  distributions server for the build scripts) are trusted for key `1BD97A6A154E7810EE0BC832E2F38302C8075E3D`. Update
  the version with the Gradle wrapper.
- Sources and Javadoc of a dependency are covered when its module is trusted through a `trusted-key` entry. A
  dependency verified only by per-artifact entries needs entries for these archives as well.

A successful build alone does not verify that IDE import has all required metadata.

### Checksum fallbacks

Checksum fallback artifacts must be reviewed in `gradle/dependency-checksum-fallback-allowlist.tsv`:

```text
<group:name:version>\t<artifact-file-name>\t<review-rationale>
```

Keep the allowlist exact and sorted. `verifyDependencySignaturePolicy` fails when a fallback artifact is missing from
the allowlist, when an allowlist entry is stale, or when an entry has no rationale.

Gradle verifies an artifact by its checksum only if the artifact has no signature or if every key which signed it is
ignored. The policy treats a checksum as fallback if it has a reason (Gradle writes `Artifact is not signed`, `A key
couldn't be downloaded` or `PGP signature verification failed!`) or if neither a `pgp` entry nor a `trusted-key` entry
for the module names a key which is not ignored. This applies to every checksum kind which Gradle verifies (`md5`,
`sha1`, `sha256` and `sha512`), also if the metadata of this repository uses only `sha256` today. It checks every entry
in `gradle/verification-metadata.xml`, not only the resolved dependency graph, because Gradle also verifies parent
POMs, imported BOMs and artifacts of other platforms against it. Entries for versions no build uses therefore also
need an allowlist entry until they are removed.

Gradle writes a reason once and keeps it when it regenerates the metadata. After a refreshed keyring adds a key,
remove the key from `ignored-keys`, delete the component entries of the artifacts it signs and run
`resolveAndVerifyDependencies --write-verification-metadata pgp,sha256` so Gradle writes them again with the current
result. Do not remove reasons by hand: the policy cannot see which key signed an artifact, so a wrongly removed reason
can hide a checksum-only artifact.

`ignored-keys` is only for signing keys that no key server publishes. `verifyDependencySignaturePolicy` fails when a
global or artifact-level ignored key is in `gradle/verification-keyring.keys`. Gradle never verifies a signature made
with an ignored key, also when the keyring contains the key, so such an entry reduces the artifacts it signs to their
checksums without need.

Executable Maven artifacts (`.exe` files) must have explicit entries in `gradle/verification-metadata.xml` for the
resolved classifier. `verifyDependencySignaturePolicy` fails when a resolved executable is covered only by a broad
`trusted-key` rule or when executable metadata remains for an older unresolved version of the same tool. The build
resolves no such artifact today.
