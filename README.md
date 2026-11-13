# Tor build

The Tor build contains the Tor integration of Bisq:

- `tor`: starts, controls and connects to Tor, and publishes onion services (`TorService`). Its `PasswordDigest`
  is a copy of the one class of jtorctl, the Java library of the Tor control protocol, which the Tor build used. It
  keeps the 3-clause BSD license of jtorctl in its header.
- `tor-common`: the torrc generation and the copies of Bisq utilities which the Tor build uses.
- `jsocks`: a copy of the SOCKS library. It keeps its own license, the LGPL. See its README.
- `tor-local-network`: a tool which starts a private Tor network for tests.
- `tor-platform`: the dependency constraints of the Tor build.

## No dependencies on other Bisq modules

This repository was extracted from Bisq 2, where it lived in `network/tor` and then in `tor/`. Its history before the
extraction is in Bisq 2.

The Tor build does not depend on other Bisq modules or on the `build-logic` build of Bisq. Do not add such a
dependency.

- `build-logic` contains the Gradle plugins of the Tor build. `tor-binary` and `gradle-tasks` exist only here. The
  other plugins are copies of plugins in the `build-logic` of Bisq 2 and keep their plugin IDs. `commons` only has
  the two convention plugins which the Tor build applies, and `COMPOSITE_PROJECTS_TO_INCLUDE` of `maven-publisher`
  names only `tor`. The copies were taken from Bisq 2 main 7767b8b319. This repository has changed
  `bisq.java-conventions`, `LocalMavenPublishPlugin` and `BisqToolchainResolver` since, so these differ from their
  originals: compare a change of a plugin in Bisq 2 with the copy here before copying it.
- The classes in the packages `bisq.network.tor.common.*`, except `torrc`, are copies of classes of `bisq.common`.
  A copy keeps the sub-package and the class name: `bisq.common.util.StringUtils` becomes
  `bisq.network.tor.common.util.StringUtils`. The exception is `FileUtils`, which combines the used methods of
  `FileMutatorUtils` and `FileReaderUtils` of `bisq.common.file`. A copy only contains the members which the Tor build
  uses. A change of an original does not change its copy. A copy never uses the package of the original, because two
  classes with the same name on one class path break the Android build of bisq-mobile and make the JVM load whichever
  comes first.
- `PlatformServices` declares the operations which depend on the platform of the host application: the own process
  ID and whether the Tor build may set POSIX file permissions. Its method for the commands of the running processes is
  deprecated, because the Tor build no longer calls it, and has a default implementation. The host passes
  an implementation to `TorService`. Bisq passes `BisqTorPlatformServices` of the network module, which uses
  `FacadeProvider` and `FileMutatorUtils` of `bisq.common`. bisq-mobile calls `FileMutatorUtils.setup(false, false)`,
  so the Tor build sets no POSIX permissions there.
- The API of the Tor build only uses types of the Tor build. `TorTransportService` of the network module adapts the
  types of Bisq: it passes the `TorKeyPair` of Bisq as `OnionServiceKey`, and its `Config` implements
  `TransportConfig` of Bisq and wraps `TorTransportConfig`.
- The supported API is `TorService` with the types which it takes, returns and throws: `PlatformServices`,
  `TorTransportConfig` with `TorSandboxConfig`, `BridgeConfig` and `ConfigFileTorrcOverrides`, `OnionServiceKey`,
  `CreateOnionServiceResponse`, `TorSocksProxyFactory`, `TorSandboxStatus` and the exceptions of its methods. Bisq 1
  also uses `TorDirectories` for the paths in the Tor directory, `ExternalTorConfig` and `PluggableTransportConfig`,
  which are supported too. All other classes are internal and may change in any version without notice:
  `EmbeddedTorProcess` and the other classes which start and run the process of Tor, the sandbox, the installer of the
  bundle, the control connection and the torrc generators. An app starts and stops Tor only through `TorService`.

## Android

The node app of bisq-mobile runs `TorService` with an external Tor on Android, from API level 33. Code which runs in
this mode must only use Java APIs which Android 13 provides. This is all code which an external Tor needs: `TorService`
without the start of the embedded Tor, `ExternalTorConfig`, `TorTransportConfig`, `BridgeConfig`,
`ConfigFileTorrcOverrides`, `TorDirectories`, `TorSocksProxyFactory` with `jsocks`, the packages `controller` (with the
events and their parsers) and `onionservice`, and `OS`, `LinuxDistribution`, `StringUtils` and `FileUtils` of
`tor-common`. Only the embedded Tor runs on desktop systems alone: `EmbeddedTorProcess`, `BundledTorLibraries`, the
packages `installer` and `bridges`, `TorrcClientConfigFactory`, the torrc generators and `tor-local-network`. If the
connection fails, `TorService` fails with `ExternalTorUnavailableException`; it never starts its own Tor instead of a
configured external Tor. For example, `java.util.HexFormat` and `Stream.toList()` need API level 34, and `ProcessHandle`
does not exist on Android. The Tor build uses Guava instead of `HexFormat` and `collect(Collectors.toList())` instead of
`toList()`. Records and switch expressions can be used, because D8 desugars them for Android.

`FileUtils` of `tor-common` reads and writes UTF-8 strictly on Android as well. The originals in `bisq.common` replace
malformed input when the modern file API is turned off, as bisq-mobile does. With the copy, a damaged
`external_tor.config` which is no valid UTF-8 fails `TorService.initialize()` with a message which names the file,
instead of being read with replacement characters.

## External Tor

With `UseExternalTor 1` in `external_tor.config` of the Tor directory, Bisq uses a Tor which already runs instead of
starting its own. The connection to its control port is plain TCP. It carries the private keys of the onion services
of Bisq (`ADD_ONION`) and, with `ControlPassword`, the password. Use a `ControlPort` on the same system, or reach a Tor
on another host only over a network which no untrusted system can use, such as the internal network of Whonix. While
the control port refuses the connection, Bisq tries again for about two seconds, because the external Tor may not
listen yet. If the control port does not accept the connection within 10 seconds, or its host cannot be reached, the
start fails at once.

Bisq asks the external Tor for its SOCKS listeners (`GETINFO net/listeners/socks`) and uses the first TCP listener which
it can reach: one on a specific address at that address, one on a wildcard address (`0.0.0.0` or `::`) at the control
host. A loopback address is an address of the host of Tor, so Bisq uses it only if the control host is a loopback
address as well. If a Tor on another host listens for SOCKS connections only on its loopback address, the start fails.

`TorService.getSocket` sends SOCKS credentials derived from the stream ID, so that Tor puts the streams of different
stream IDs on different circuits. Tor does so on a SOCKS port with `IsolateSOCKSAuth`, which it sets by default. The
start with an external Tor fails if a `SocksPort` or `__SocksPort` entry of its configuration which may have opened the
SOCKS port that Bisq uses turns this off with `NoIsolateSOCKSAuth`. If the control port does not report the
configuration, as onion-grater on Whonix does not, Bisq logs that it could not check the port and starts.

## Onion services

A publication of an onion service completes once the first HSDir has stored its descriptor, which Tor reports with
`HS_DESC UPLOADED`, not at the start of the upload (`HS_DESC UPLOAD`), when no peer could find the onion service yet. It
fails if no HSDir has stored the descriptor within the upload timeout of `TorTransportConfig`. The exception is an
`UPLOAD` which a filter in front of Tor shortened, see "Whonix".

## Whonix

On Whonix, `TorService` always uses the Tor of the Whonix-Gateway and never starts its own Tor. The control port of the
Gateway is filtered by onion-grater, so the Gateway needs an updated system and the onion-grater profile of Bisq, which
Whonix ships: `sudo onion-grater-add 40_bisq`. The library authenticates without a secret, sends `ADD_ONION` with a bare
local port as target, which onion-grater rewrites to the address of the Workstation, and listens on all addresses.
Every profile delivers `HS_DESC UPLOADED` with the HSDir redacted, which completes a publication. Profiles before
September 2024 shorten `HS_DESC UPLOAD` to `<address> <auth> redacted redacted`, without the `HSDIR_INDEX` which Tor
sends with every upload of a v3 descriptor; there such an `UPLOAD` completes the publication, as before.
`TorServiceWhonixTest` answers like onion-grater; there is no test on Whonix itself. Both Whonix systems have the
markers by which `TorService` detects Whonix (`/usr/share/whonix/marker` and `/usr/share/anon-dist/marker`). On the
Whonix-Gateway, which has `/usr/share/anon-gw-base-files/gateway` as well, `TorService` does not start and tells the
user to run Bisq on a Whonix-Workstation.

## Torrc overrides

`TorTransportConfig` takes torrc overrides, entries which the application adds to the torrc of the Tor which it starts.
An external Tor gets none of them.

An override which makes Tor start a program or load a library stops the start of the embedded Tor with
`TorrcOverrideNotAllowedException` if it comes from a configuration file which the application also writes itself.
These are `ClientTransportPlugin`, `ServerTransportPlugin`, `AccelName` and `AccelDir`, in any case of the name and as
an abbreviation which Tor accepts. The application names such overrides in `ConfigFileTorrcOverrides`, together with a
hint for the message: how the user gives them instead, for example on the command line. Whoever can change such a file
could otherwise make the next start of Tor run code with the rights of the user, also with the sandbox off, which such a
file can turn off as well. The same overrides from the command line or the code of the application reach Tor.

Tor starts the program of a transport plugin entry. It passes the values of `AccelName` and `AccelDir` to the engine
loader of OpenSSL, which loads a library as the engine; `AccelName` alone loads the engine of that name from a path or
from the engine directory of OpenSSL. In the bundled Tor, that directory is below `/var/tmp/dist`, where any local user
can create files. `HardwareAccel` alone uses only the engines built into OpenSSL.

In the configuration of Bisq 2, an override comes from a configuration file if `bisq.conf` in its data directory
assigns it and the program arguments and JVM options, which count as the command line, do not.
`TorTransportConfig.from(Path, Config, Config, Config)` takes `bisq.conf` as Bisq 2 parsed it, before its substitutions
are resolved, and the command line. `bisq.conf` assigns an override also if it takes the value from elsewhere: with a
substitution such as `${x}`, whose resolved value has the origin of `x`, or with an include of a file, a URL or a
resource. If it assigns the overrides or an object above them as a whole, it assigns all of them. In addition, and
alone in `TorTransportConfig.from(Path, Config)`, an override comes from a configuration file if Bisq 2 read its value
from a file or a URL which is not one of its resources. With the bridges of the configuration, overrides of
`ClientTransportPlugin` are ignored, so they are not refused. Bisq 1 names the overrides of `--torrcOptions` and
`--torrcFile` which come from `bisq.properties` or another config file.

Tor reads every torrc value as text. In the configuration of Bisq 2, a value without quotes can be a number or a
boolean, and Bisq 2 turns program arguments and JVM options into numbers and booleans where it can. Such a value reaches
Tor as its text: `AvoidDiskWrites = 1` gives `AvoidDiskWrites 1`, and `true` stays `true`, which Tor refuses for its
boolean options, as they take `0` or `1`. A list is no torrc value and fails with an error which names the path.

## Bridges and pluggable transports

`TorTransportConfig` takes a `BridgeConfig`: no bridges, the built-in bridges of one type of the Tor Browser version of
the bundle (`obfs4`, `snowflake` or `meek`), or bridge lines of the user. The built-in bridges and the programs of the
transports come from `pluggable_transports/pt_config.json` of the expert bundle, which Tor Browser uses as well, so they
change with `tor.version`.

For the Tor which Bisq starts, `TorService` writes `UseBridges 1`, one `Bridge` entry per bridge and one
`ClientTransportPlugin` entry per program which the bridges need. Tor splits a `ClientTransportPlugin` entry at white
space, and the Bisq data directory of macOS is below "Application Support". Tor therefore runs in the directory of the
bundle and gets the path of a program relative to it. If a bridge needs a transport without program, the start fails
with `BridgesUnavailableException`: Tor must not connect without the bridges, because the user relies on them to get
around a block or to hide the use of Tor. With bridges in the configuration, torrc overrides of `UseBridges`, `Bridge`
and `ClientTransportPlugin` are ignored. Bisq does not log the bridge lines, because a bridge which a user got privately
is blocked once it is known.

An external Tor uses the bridges of its own configuration. `TorService` logs a warning if the configuration of Bisq has
bridges as well.

In the configuration of Bisq 2 (`TorTransportConfig.from`), `builtInBridges` names the type of the built-in bridges and
`bridges` lists bridge lines. Both are optional, and at most one may be set.

## Sandbox

The library can run the Tor which it starts in the sandbox of the operating system with sandy 1.2.0 (Landlock and
seccomp on Linux, Seatbelt on macOS, an AppContainer on Windows). The policy is a TOML file per platform in
`tor/src/main/resources/sandy/policy/`; it decides how strongly Tor is isolated, and the library only fills in the
values of a start (the paths of the Tor directory, the ports, the forwarded onion service targets, the environment
and on Windows the AppContainer name), each written as a TOML value. The base of the policy is the maximum lockdown:

- Tor has a network of its own. Bisq reaches its control and SOCKS ports through ports which sandy relays out of the
  sandbox, Tor reaches the onion services of Bisq through ports which sandy forwards, and Tor connects out only
  through sandy's egress broker, which reaches public addresses only (`Socks5Proxy` in the torrc).
- Tor may read its torrc, the bundle and the empty configuration of its OpenSSL, and execute only its binary and the
  libraries of the bundle; it may write only its data directory; on Linux and macOS every other path looks missing to
  it, except that on Linux the directories above a granted path exist, without their contents.
- Tor cannot start other processes (see "Pluggable transports" below for the exception), cannot signal processes
  outside the sandbox, and ends when Bisq ends.

The policy also lists weaker fallback levels. sandy takes the first level that the host can enforce, and skips a level
only for a lasting shortfall of the host, never for a failure that can pass or a port another process holds, so no
other user of the host can choose a weaker level:

| Level | Host |
|---|---|
| `base` | Linux 6.12 or newer with user namespaces which sandy may use and the fix of Landlock erratum 3, macOS, Windows 10 1809 or newer |
| `contained` (Linux) | Linux 5.13 to 6.11 with the same: a PID namespace isolates the signals of Tor, and Tor may start processes in it, which end with Tor |
| `host-network` | user namespaces restricted (Ubuntu 23.10 and newer) or off, or no fix of Landlock erratum 3: the network of the host, no egress broker, no view; on Windows a separate AppContainer |
| `host-network-signals` (Linux) | as `host-network`, below Linux 6.12: Tor can signal the processes of the user and does not end with Bisq |

Before each start Bisq writes the policy to the standard input of `sandy check --json`, writes the torrc for the
level which sandy selected, and starts Tor with `sandy run --level` and the same policy on standard input. There is no
policy file which anything could change in between, and `--level` makes sandy refuse rather than take another level
if the host changed. Bisq names itself as the parent of Tor (`--parent-pid`) only in a level which ends Tor with Bisq;
sandy refuses the option in `host-network-signals`. In such a level Tor gets no `__OwningControllerProcess`, because
sandy ends it with Bisq; in the PID namespace of `contained` Tor cannot see Bisq's process and would exit at its first
owner check. Bisq never runs `sandy setup`. Once Tor answers on its control port, `TorService.getSandboxStatus()`
names the level and says what it gives up. Of sandy's warnings Bisq shows only those which name the fallback level
that Tor runs or something on this host that can make Tor fail or weaken its sandbox, such as a Windows session
without a desktop; the others describe limits of a platform that the policy accepts (`Sandy.SHOWN_WARNING_IDS`). A
torrc override of a proxy option refuses the sandboxed start, because the egress broker is Tor's only way out, and so
does an override of `GeoIPFile` or `GeoIPv6File`: in its sandbox Tor reads only the GeoIP files of its installation.
The broker reaches public addresses only, so in a level with the broker a test network, whose directory authorities
listen on 127.0.0.1, refuses the start before Tor runs, and so do bridges which are all on loopback, private or
link-local addresses; with some of them Bisq logs a warning.

In the configuration of Bisq 2 the sandbox is on unless `sandbox.enabled = false` turns it off, and it allows no
pluggable transports unless `sandbox.allowPluggableTransports = true`. The `TorTransportConfig` constructor without a
`TorSandboxConfig` leaves the sandbox off. Gradle resolves the release archive of sandy 1.2.0 for the platform of the
build as a verified dependency, the build checks it against the signed checksums of the release and packages its
binary, and `-Psandy.package=false` builds without sandy (see `tor/src/main/resources/sandy/README.md`, which also says
how a new release of sandy is checked before the build moves to it: its signed checksums, a rebuild from the tag, and a
review of the source diff).

Tor runs without the sandbox, and `TorService.getSandboxStatus()` says why, if:

- the configuration turns it off (`DISABLED`);
- Bisq uses an external Tor (`EXTERNAL_TOR`), which includes Whonix and Android.

If the sandbox is on but no level can be enforced, or sandy cannot tell now, the start fails with
`SandboxUnavailableException`, which names the reason and how the user of the application turns the sandbox off. So
does a run which sandy ends before Tor runs, for example because another process took a port of the policy after the
check. Tor can exit with the status of such a refusal, 125, as well, so Bisq decides by the status record of the run,
which sandy writes into `sandy/run-status` (`--status-file`) and which Tor can neither write nor remove: only a record
which shows that sandy ended the run before Tor ran gets the advice to turn the sandbox off. Every other end of a
sandboxed Tor before it answers on its control port is a failed start without that advice. Bisq chooses the ports of
the policy and releases them before sandy binds them, so such a refusal of `sandy run`, and an exit 125 of
`sandy check`, which tries the ports, can pass: the start then runs once more with other ports, within the same
`initialize()`, and only a second refusal fails it. The error of a failed start names `tor.log` and quotes the part
of it which this start wrote: Tor writes the reason of a failed start to its standard output, sandy and the system
write theirs to the standard error, and `tor.log` holds both. In the sandbox, sandy and Tor write this file and Tor can
rewrite it, so the error names what Bisq knows itself (the exit status and the status record) first and labels the
quote as written by sandy and by Tor in its sandbox and not verified by Bisq. In the same way an error which quotes a reply of Tor on its control connection, or a field of one of its events,
says what Bisq knows first and then labels the quote "Tor reported (not verified by Bisq)".

On Linux sandy refuses to run as root or with capabilities, because Tor would keep them in the sandbox (Landlock does
not restrict `chmod` or `chown`). A node which runs as root, as is common in containers, therefore fails its sandboxed
start; run it as an unprivileged user, or turn the sandbox off. Bisq installs sandy into `sandy/` of the Tor directory
and runs it from there, so a Tor directory on a mount with `noexec` fails the sandboxed start as well.

### Pluggable transports

The transports of bridges are programs which Tor starts. The sandbox does not allow them by default: a sandboxed start
whose bridges use a transport fails with `PluggableTransportsNotAllowedException`, a `SandboxUnavailableException`
which names the transports and returns them with `getTransportNames()`, so that the application can tell the user how
to allow them in its own terms or let the user choose other bridges. With
`allowPluggableTransports` of `TorSandboxConfig` (in Bisq 2 `sandbox.allowPluggableTransports = true`), Tor may start
the programs of the transports of the configured bridges in its sandbox, which `TorSandboxPolicy` adds to the policy,
and sandy ends them with Tor (`children = "contained"`). Programs which torrc overrides would start
(`ClientTransportPlugin`, `ServerTransportPlugin`, also abbreviated) refuse the sandboxed start; with bridges in the
configuration this leaves `ServerTransportPlugin`, because the overrides of the bridge keys are ignored. To use
transports without any sandbox, turn the sandbox off.

The transports decide the network:

- obfs4 connects only to the IP address of its bridge. On Linux Tor keeps its network of its own, and the transport
  connects through the egress broker, which Tor passes to it as its proxy (`linux-transports.toml`).
- meek_lite and webtunnel resolve the names of their servers, which the broker refuses, snowflake needs UDP, which the
  broker does not carry, and conjure refuses a proxy. With any of them, Tor and its transports get the network of the
  host, with the view and the containment of the transports kept where the host gives them
  (`linux-transports-direct.toml`).
- On macOS every transport gets the network of the host (`macos-transports-direct.toml`): the private network of sandy
  has no loopback there on which Tor could reach its transports.
- Windows refuses transports in the sandbox: Tor cannot create the named pipes to its transports in an AppContainer
  (measured, `CreateNamedPipeA` fails with access denied).

The levels of the Linux templates: `base`, then `host-network` without the view where user namespaces are restricted
or off, then `host-network-signals` below Linux 6.12, where sandy cannot contain the transports either: they end when
Tor closes their standard input. The macOS template has the base alone: it has the network of the host already, and a
Mac gives the view whenever Unix sockets are denied, so a level without the view would fail wherever the base fails.

Measured with Tor 0.4.9.14 and lyrebird 0.8.1 of Tor Expert Bundle 15.0.25 under sandy 2.2.1: obfs4, meek_lite and
webtunnel bootstrapped on Ubuntu 22.04 and 25.10, obfs4 and meek_lite also on macOS 27, and obfs4 also through the
egress broker. On macOS webtunnel failed in the sandbox of sandy 2.2 (`x509: OSStatus -26276`): it verifies its server
only with the certificate verifier of the system (trustd), a Mach service which sandy did not let programs reach, while
meek_lite falls back to a root certificate of its own. Since sandy 2.4 the macOS transports template can allow the trust
agent of the user, `com.apple.trustd.agent`, the one service this verification needs: a Go program that verifies a real
certificate chain with the system verifier fails under sandy 2.4 without it and passes with it (measured on macOS 27).
`TorSandboxPolicy` names it only when the bridges use a transport which verifies its server with the system: webtunnel,
and snowflake and conjure, whose TLS also uses the system roots (not measured). obfs4, which uses no TLS, meek_lite and
Tor without transports get no Mach service. A webtunnel bootstrap on macOS under sandy 2.4 has not been measured yet.
snowflake did not bootstrap on the test network even without the sandbox, and conjure was not measured.

Platform notes, from an end-to-end test of Tor 0.4.9.14 under sandy 2.2.0 with onion services on Ubuntu 22.04, Ubuntu
25.10, Windows 11 and macOS 27:

- macOS: the expert bundle's programs are not code signed, and Apple silicon kills unsigned code, so the installer
  signs them ad hoc. Tor and sandy must both be arm64 code there.
- Windows: `tor.exe` loads `user32.dll`, so the policy allows the win32k system calls, and Tor must start in a session
  whose window station admits AppContainers, such as a desktop session. As a service, in session 0 or in a session
  over SSH it ends with `STATUS_DLL_INIT_FAILED` before it runs. `sandy check` warns in session 0 but does not refuse,
  and it detects no other window station which admits no AppContainer; Bisq logs the warning with the check and
  reports a failed start of Tor which names the session as the likely cause.
- Linux: the bundled tor takes the loader, glibc and zlib from the system, which the minimal system set of sandy
  grants (the loader and the libraries in `/usr/lib`, `/usr/lib64`, `/lib` and `/lib64`), and its other libraries from
  `bin/`, which `LD_LIBRARY_PATH` names; a Tor directory whose path contains `:` or `;` fails the start, because the
  loader splits the variable there. The bundled tor is built for this layout of the file system, so it runs neither in
  the sandbox nor without it on NixOS or Guix, whose libraries lie in their stores: there Bisq needs an external Tor.
- Linux: in a level with the network of the host (`host-network`, `host-network-signals` and the base of
  `linux-transports-direct.toml`), sandy asks the kernel through `inet_diag` (netlink `NETLINK_SOCK_DIAG`) who
  connected to a forwarded onion service port, and refuses connections of other users. `sandy check` does not try
  this. On a host where it fails, for example a kernel without `inet_diag` or a container that denies netlink
  sockets, the check passes, and `sandy run` refuses to start Tor with status 125, which Bisq reports as a sandbox
  refusal with the advice to turn the sandbox off (sandy `crates/sandy-linux/src/peer.rs`; not run on such a host).
- Linux: Tor gets no `/proc/meminfo` (a grant of a `/proc` path would cost the PID namespace of `contained`), from
  which it derives the default of `MaxMemInQueues`. So on every platform Bisq computes that default as Tor does, from
  the size of the memory which the JVM reports (the limit of a container if one applies), and writes it into the
  torrc of a sandboxed Tor unless a torrc override sets it; if the JVM cannot tell the size, it writes 512 MB.

The Tor directory has the parts `bin/` (the installed bundle), `data/` (the DataDirectory of Tor, the only directory
which a sandboxed Tor may write) and `sandy/`; the torrc, `openssl.cnf`, the logs and `external_tor.config` lie in the
Tor directory itself. Bisq never deletes the `lock` file of Tor in `data/`: Tor locks it while it runs, so a file which
an ended Tor left blocks no start, and a Tor which still runs on the directory makes the next one exit. A compromised
Tor in the sandbox can leave files in `data/` which exploit the next Tor that parses them, and a Tor without the
sandbox has all rights of the user. So before each start `data-mode` in the Tor directory records whether Tor runs in
the sandbox, and before Tor starts without the sandbox on a `data/` which a sandboxed Tor may have written (the record
says so, or it is missing while `data/` existed before the start), Bisq clears `data/`. Tor then selects new entry
guards and downloads the directory documents again. A start in the sandbox keeps `data/`. Tor logs to its
standard output. Bisq writes the standard output and the standard error of Tor, or of sandy, in the order in which
they were written to `tor.log`, which it keeps across starts and moves to `tor.log.1` before a start when it exceeds
10 MiB. Before a start of the embedded Tor, `TorDirectoryMigration` moves the state of Tor from the layout before into
`data/`, deletes the files of the old layout which it knows, and keeps everything else, such as the onion service key
of Bisq 1 in `hiddenservice/`. At every start it also deletes the logs of versions up to 1.0.1, `tor-stdout.log`,
`tor-stdout.log.1` and `tor-stderr.log`; a file which is missing needs no deletion, so no record of the deletion is
kept.

`EmbeddedTorProcess` starts Tor, or sandy, with the `setsid` program of the system in a session of its own, if the
system has one, as Linux does. A Ctrl+C in the terminal of Bisq then does not reach Tor, which would otherwise exit at
once, before the shutdown of Bisq has used it. macOS has no `setsid`, so there Tor stays in the process group of
Bisq.

## Build

Run these commands in the repository root:

- `./gradlew build` builds the Tor build and runs its tests and checks: the dependency verification, the Gradle wrapper
  checksums and the pinned GitHub Actions.
- `./gradlew integrationTest` runs the integration tests, which start Tor; `build` does not run them. A test skips
  itself if this host lacks what it needs. They start the bundled tor of the build. `PrivateTorNetworkOnionServiceTest`
  starts a private Tor network on this host, so it needs no internet; to create the keys of its directory authorities
  it needs tor and tor-gencert in `PATH` (on Debian and Ubuntu the package `tor`), and the tor in `PATH` is also its
  external Tor. Two peers publish onion services and exchange messages, also after a restart, through the SOCKS5 proxy
  and through an external Tor. `-Ptor.publicNetworkTests=true` adds `PublicTorNetworkOnionServiceTest`, which runs
  these peers and a peer in the sandbox on the public Tor network.
- `./gradlew :tor:verifyTorBinary` downloads and verifies the Tor expert bundle. See
  [build-logic/tor-binary/README.md](build-logic/tor-binary/README.md).
- `./gradlew dependencySignatureReport` writes [docs/dependency-signature-report.md](docs/dependency-signature-report.md)
  after a change of the dependencies or of `gradle/verification-metadata.xml`.

The build cache is on (`org.gradle.caching=true`), so a test task whose inputs did not change takes its result from the
cache (`FROM-CACHE`) or is `UP-TO-DATE`, and a build can pass without running a test. `./gradlew test --rerun` and
`./gradlew integrationTest --rerun` run the tests again; `--rerun-tasks` would also download the Tor bundle again.

CI runs `build` on Linux, macOS and Windows, and `integrationTest --rerun` on Linux x86_64
(`.github/workflows/build.yml`). The integration job installs the packages `tor` and `busybox` and allows unprivileged
user namespaces, which Ubuntu 24.04 restricts, so that the tests also run in the levels `base` and `contained` of the
Linux policy, which hosts without this restriction get. It fails if `SandboxEnforcementTest` skipped a test.
`.github/workflows/public-network-test.yml` runs `PublicTorNetworkOnionServiceTest` once a week and on request.

`gradle.properties` defines `version` (the version of the artifacts), `tor.version` (the version of the Tor expert
bundle) and `tor.binaryVersion` (the version of the tor daemon in the bundle, which Bisq 2 shows). Bisq 2 reads all
three from `tor/gradle.properties`. `tor.binaryVersion` is set by hand, so `verifyTorBinaryVersion`, which every build
of `tor.zip` runs, fails if the tor of the bundle reports another version. The signed checksum file of `tor.version`
pins each platform's bundle; a change of `tor.version` needs that release's signed checksum file (see
[build-logic/tor-binary/README.md](build-logic/tor-binary/README.md#pin-the-bundles-of-a-release)).

`version` belongs to the Tor build. It follows neither Bisq 1 nor Bisq 2, which both use the Tor build, nor
`tor.version`, because the code and the Tor expert bundle change independently. Raise it with every change of the
artifacts, following semantic versioning:

- major: a change which requires a change in Bisq 1 or Bisq 2, such as an incompatible change of the API;
- minor: a new feature, or a new Tor expert bundle which needs a change of the code;
- patch: a fix, or a new Tor expert bundle without a change of the code.

`gradle/libs.versions.toml` and the constraints of `tor-platform` have the versions of Bisq 2: every catalog version is
`strictly`, and the composite build of Bisq 2 accepts one version of a module. Nothing checks this automatically.
Before Bisq 2 records a new commit of `tor/`, compare them with a checkout of Bisq 2; both commands print nothing if
every version of this build equals the one of Bisq 2:

```bash
bisq2=/path/to/bisq2
sed -n '/^\[versions\]/,/^\[libraries\]/{/=/p}' gradle/libs.versions.toml |
    while IFS= read -r line; do grep -qxF "$line" "$bisq2/gradle/libs.versions.toml" || echo "differs: $line"; done
constraints() {
    tr -d '\n' < "$1" | grep -oE 'api\("[^"]+"\) *\{ *version *\{ *require\("[^"]+"\)' | sort
}
comm -23 <(constraints tor-platform/build.gradle.kts) <(constraints "$bisq2/platform/build.gradle.kts")
```

`tor.zip` and `TorBuildVersion` are generated by Gradle tasks. An IDE build which does not run Gradle tasks needs one
Gradle build first.

`tor.zip` contains the files of the Tor expert bundle of the platform of the build, which `TorService` installs into the
Tor directory: Tor, its libraries, the GeoIP files and the pluggable transports (`lyrebird` and `conjure-client` with
their configuration `pt_config.json`). Linux x86_64, Linux ARM64, macOS and Windows x86_64 take the bundle of
`tor.version`; its tor must be `tor.binaryVersion` (`build-logic/tor-binary/README.md`). Every build downloads and
verifies the expert bundle of its platform. The download needs archive.torproject.org; it fails if it gets no connection
in 30 seconds or no data for 60 seconds, and is then tried once more. With `--offline`, the build keeps a bundle which
it downloaded before. There is no expert bundle for
Windows ARM64, and the build never packages the programs of another architecture, so a build in an ARM64 JVM on Windows
fails when it needs the bundle.

## Use in Bisq 1 and Bisq 2

Bisq 1 and Bisq 2 include this repository as the Git submodule `tor/` and as an included Gradle build. Each records one
commit of this repository. In the composite build of an app, Gradle uses the dependency verification metadata of the
app, so a new dependency of the Tor build must also be added to `gradle/verification-metadata.xml` of Bisq 1 and of
Bisq 2.

To change the Tor code for an app, commit the change here, push it, and then commit the new commit of `tor/` in the
app. The apps describe the update of `tor/` in their own documentation: Bisq 1 in `docs/build.md` ("Tor submodule"),
Bisq 2 in its `README.md` ("Tor Submodule").
