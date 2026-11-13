/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package bisq.network.tor;

import bisq.network.tor.common.platform.OS;
import bisq.network.tor.common.torrc.DirectoryAuthority;
import bisq.network.tor.controller.exceptions.TorBootstrapFailedException;
import bisq.network.tor.process.ControlPortProbe;
import bisq.network.tor.process.LoopbackPorts;
import bisq.network.tor.process.TorDataDirectoryMode;
import bisq.network.tor.process.TorDirectories;
import bisq.network.tor.process.TorListenerPorts;
import bisq.network.tor.sandbox.SandboxUnavailableException;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import com.google.common.base.Throwables;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Starts the bundled tor of Linux through TorService up to the bootstrap. All connections of Tor go to a closed local
 * port, or in the sandbox to an address of the documentation range, which no network routes and which the egress
 * broker of sandy refuses, so Tor makes no connection to the Tor network and cannot bootstrap. The start must then
 * fail and stop Tor.
 */
@Timeout(60)
class LocalEmbeddedTorStartTest {
    // A certificate of the right form (52 bytes in base64), which no bridge has: the transport never reaches one. A
    // sandboxed start refuses bridges on addresses of this host where Tor connects out through the egress broker.
    private static final String OBFS4_BRIDGE_ON_A_DOCUMENTATION_ADDRESS = "obfs4 192.0.2.1:1 " +
            "0123456789ABCDEF0123456789ABCDEF01234567 cert=" + "A".repeat(70) + " iat-mode=0";
    // The program of obfs4 and meek_lite in the bundle
    private static final String LYREBIRD = "lyrebird";

    @TempDir
    Path torDir;

    @Test
    void aStartWithoutBootstrapFailsAndStopsTor() throws Exception {
        assumeBundledTorOfLinux();

        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        // The start got to the bootstrap: Tor accepted the torrc and the command line, the control connection was
        // authenticated and checked, and TorService enabled the network.
        String torrc = Files.readString(torDir.resolve("torrc"));
        assertThat(torrc).contains("AvoidDiskWrites 1", "Socks5Proxy 127.0.0.1:1", "HashedControlPassword 16:");
        assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.DISABLED);
        assertThatNoTorOfThisTestRuns();
    }

    // Tor locks the file while it runs, so a file which an ended Tor left does not keep the next Tor from starting.
    @Test
    void aLockFileWhichAnEndedTorLeftDoesNotBlockTheStart() throws Exception {
        assumeBundledTorOfLinux();
        // The data directory of a Tor without the sandbox, which a start without the sandbox keeps
        Files.createDirectories(torDir.resolve("data"));
        TorDataDirectoryMode.prepareWithoutSandbox(new TorDirectories(torDir), true, true);
        Files.createFile(torDir.resolve("data").resolve("lock"));
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        // The start got to the bootstrap, so Tor ran with the data directory.
        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));
        assertThatNoTorOfThisTestRuns();
    }

    /**
     * Runs only with -Psandy.package=false, which builds without sandy.
     */
    @Test
    void aSandboxedStartWithoutSandyFailsBeforeTorStarts() {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") == null,
                "The build packaged a sandy binary");
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "Turn the sandbox off to test.");
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false, BridgeConfig.NONE, sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("no sandy binary")
                .hasMessageContaining("Turn the sandbox off to test.");
        assertThatNoTorOfThisTestRuns();
    }

    // The data directory of the application can hold "#", which starts a comment in an unquoted torrc value.
    @Test
    void aStartWithAHashInTheTorDirectoryReachesTheBootstrap() throws Exception {
        assumeBundledTorOfLinux();
        Path hashTorDir = torDir.resolve("Bisq#1").resolve("tor");
        var transportConfig = new TorTransportConfig(hashTorDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        assertThat(Files.readString(hashTorDir.resolve("torrc")))
                .contains("DataDirectory \"" + hashTorDir.resolve("data").toAbsolutePath() + "\"\n");
        assertThat(hashTorDir.resolve("data").resolve("state")).exists();
        assertThatNoTorOfThisTestRuns(hashTorDir);
    }

    /**
     * A shutdown while the start waits for the bootstrap ends the start at once with a failure, instead of after the
     * bootstrap timeout, and no Tor stays. The shutdown comes 2 seconds after Tor answers on its control port: the
     * start has then created the process and the controller which the shutdown stops, and has authenticated, which
     * takes milliseconds.
     */
    @Test
    @Timeout(90)
    void aShutdownDuringTheStartEndsTheStartAndStopsTor() throws Exception {
        assumeBundledTorOfLinux();
        var transportConfig = new TorTransportConfig(torDir, 60_000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        var torService = new TorService(transportConfig, new LocalPlatformServices());
        CompletableFuture<Boolean> start = CompletableFuture.supplyAsync(() -> torService.initialize().join());
        awaitControlPortOfTheTorrc();
        Thread.sleep(2000);

        long shutdownStart = System.currentTimeMillis();
        assertThat(torService.shutdown().get(30, TimeUnit.SECONDS)).isTrue();

        assertThatThrownBy(() -> start.get(30, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class)
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));
        assertThat(System.currentTimeMillis() - shutdownStart).isLessThan(30_000);
        assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.NOT_STARTED);
        assertThatNoTorOfThisTestRuns();
    }

    private void awaitControlPortOfTheTorrc() throws Exception {
        Path torrcPath = torDir.resolve("torrc");
        long deadline = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < deadline) {
            if (Files.exists(torrcPath)) {
                Matcher controlPort = Pattern.compile("ControlPort 127\\.0\\.0\\.1:([0-9]+)")
                        .matcher(Files.readString(torrcPath));
                if (controlPort.find() && ControlPortProbe.isTorAnswering(Integer.parseInt(controlPort.group(1)))) {
                    return;
                }
            }
            Thread.sleep(50);
        }
        throw new AssertionError("Tor did not answer on its control port");
    }

    /**
     * Runs only if the build packaged a sandy binary, which it does unless -Psandy.package=false. A bridge on an
     * address of the documentation range keeps Tor off the Tor network: the egress broker of sandy refuses it, and in
     * a level with the network of the host no network routes it.
     */
    @Test
    void aSandboxedStartReachesTheBootstrap() throws Exception {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "");
        String bridgeLine = "192.0.2.1:1 0123456789ABCDEF0123456789ABCDEF01234567";
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(), Map.of(), false,
                BridgeConfig.custom(List.of(bridgeLine)), sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        // Tor answered in its level before the bootstrap failed.
        TorSandboxStatus status = torService.getSandboxStatus();
        assertThat(status.isSandboxed()).isTrue();
        assertThat(status.getLevel()).isIn("base", "contained", "host-network", "host-network-signals");
        assertThat(torDir.resolve("sandy").resolve("sandy")).isRegularFile();
        // Tor connects out through the egress broker in the levels with a network of its own, and directly in the
        // others. It gets no /proc/meminfo, so Bisq sets the limit Tor would derive from it.
        String torrc = Files.readString(torDir.resolve("torrc"));
        if (status.isHostNetwork()) {
            assertThat(torrc).doesNotContain("Socks5Proxy");
        } else {
            assertThat(torrc).containsPattern("Socks5Proxy 127\\.0\\.0\\.1:[0-9]+\n");
        }
        assertThat(torrc).containsPattern("MaxMemInQueues [0-9]+ bytes\n").contains("Bridge " + bridgeLine + "\n");
        assertThatNoTorOfThisTestRuns();
    }

    /**
     * Runs only if the build packaged Tor and sandy, on any platform. A Tor directory named through a symbolic link, as
     * with a link to the data directory of the current version, reaches the bootstrap in the sandbox, where Tor is
     * given the real path ({@link TorDirectories#withLinksResolved}). With sandy before 1.1.0, Tor in the sandbox of
     * macOS exited with "Unable to open configuration file" for the path through the link.
     */
    @Test
    void aSandboxedStartWithTheTorDirectoryBehindALinkReachesTheBootstrap() throws Exception {
        assumeTrue(getClass().getClassLoader().getResource("tor.zip") != null, "The build packaged no Tor bundle");
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        assumeTrue(!OS.isWindows(), "A symbolic link needs a privilege on Windows");
        Path link = Files.createSymbolicLink(torDir.resolveSibling(torDir.getFileName() + "-link"), torDir);
        try {
            var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "");
            var transportConfig = new TorTransportConfig(link, 3000, 1000, false, Set.of(), Map.of(), false,
                    BridgeConfig.custom(List.of("192.0.2.1:1 0123456789ABCDEF0123456789ABCDEF01234567")),
                    sandboxConfig);
            var torService = new TorService(transportConfig, new LocalPlatformServices());

            assertThatThrownBy(() -> torService.initialize()).satisfies(e ->
                    assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));
            assertThat(torService.getSandboxStatus().isSandboxed()).isTrue();
            assertThat(Files.readString(torDir.resolve("torrc"))).doesNotContain(link.toString());
            // Tor got the real path, which on macOS differs from that of the temporary directory (/private/var).
            assertThatNoTorOfThisTestRuns(torDir.toRealPath());
        } finally {
            Files.delete(link);
        }
    }

    /**
     * Runs only if the build packaged a sandy binary. A compromised Tor in the sandbox can leave files in its data
     * directory which exploit the next Tor that parses them. A start without the sandbox after one in the sandbox runs
     * Tor on a cleared data directory; a start in the sandbox after one without keeps it.
     */
    @Test
    void aStartWithoutTheSandboxAfterOneInTheSandboxRunsTorOnAClearedDataDirectory() throws Exception {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        var inTheSandbox = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(), Map.of(), false,
                BridgeConfig.custom(List.of("192.0.2.1:1 0123456789ABCDEF0123456789ABCDEF01234567")),
                new TorSandboxConfig(true, true, false, 32, "bisq2", ""));
        var withoutTheSandbox = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("Socks5Proxy", "127.0.0.1:1"), false);
        Path dataDir = torDir.resolve("data");

        assertThatTheStartGetsToTheBootstrap(inTheSandbox);
        Path leftInTheSandbox = Files.writeString(dataDir.resolve("left-by-tor"), "in the sandbox");
        assertThatTheStartGetsToTheBootstrap(withoutTheSandbox);
        assertThat(leftInTheSandbox).doesNotExist();

        Path leftWithoutTheSandbox = Files.writeString(dataDir.resolve("left-by-tor"), "without the sandbox");
        assertThatTheStartGetsToTheBootstrap(inTheSandbox);
        assertThat(leftWithoutTheSandbox).hasContent("without the sandbox");
        assertThatNoTorOfThisTestRuns();
    }

    private static void assertThatTheStartGetsToTheBootstrap(TorTransportConfig transportConfig) {
        var torService = new TorService(transportConfig, new LocalPlatformServices());
        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));
    }

    /**
     * Runs only if the build packaged a sandy binary. Another process takes the SOCKS port of the policy after Bisq
     * released it: before sandy check, which then cannot tell, or after it, so that sandy run refuses to start Tor.
     * The start runs once more with other ports, and Tor gets to the bootstrap. The stand-in for the other process
     * takes the port when TorService logs the ports, or the level of the check.
     */
    @ParameterizedTest
    @ValueSource(strings = {"Tor listener ports", "sandy selected the level"})
    void aStartWhichSandyRefusesOverATakenPortRunsOnceMore(String takeThePortAt) throws Exception {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "");
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(), Map.of(), false,
                BridgeConfig.custom(List.of("192.0.2.1:1 0123456789ABCDEF0123456789ABCDEF01234567")), sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());
        var otherProcess = new PortTaker(takeThePortAt);
        Logger torServiceLogger = (Logger) LoggerFactory.getLogger(TorService.class);
        otherProcess.start();
        torServiceLogger.addAppender(otherProcess);
        try {
            assertThatThrownBy(() -> torService.initialize())
                    .satisfies(e -> assertThat(Throwables.getRootCause(e))
                            .isInstanceOf(TorBootstrapFailedException.class));
        } finally {
            torServiceLogger.detachAppender(otherProcess);
            otherProcess.release();
        }

        assertThat(otherProcess.takenPort).isPresent();
        assertThat(otherProcess.events).anyMatch(event -> event.startsWith("sandy refused to start Tor. Bisq tries " +
                "once more with other ports"));
        assertThat(torService.getSandboxStatus().isSandboxed()).isTrue();
        assertThatNoTorOfThisTestRuns();
    }

    // Takes the SOCKS port of the first start of Tor once TorService logs the message
    private static class PortTaker extends AppenderBase<ILoggingEvent> {
        private final String message;
        private final List<String> events = new CopyOnWriteArrayList<>();
        private volatile Optional<TorListenerPorts> listenerPorts = Optional.empty();
        private volatile Optional<ServerSocket> takenPort = Optional.empty();

        PortTaker(String message) {
            this.message = message;
        }

        @Override
        protected void append(ILoggingEvent event) {
            events.add(event.getFormattedMessage());
            Object[] arguments = event.getArgumentArray();
            if (listenerPorts.isEmpty() && arguments != null && arguments.length > 0 &&
                    arguments[0] instanceof TorListenerPorts ports) {
                listenerPorts = Optional.of(ports);
            }
            if (takenPort.isEmpty() && event.getMessage().startsWith(message)) {
                try {
                    takenPort = Optional.of(new ServerSocket(listenerPorts.orElseThrow().socks().outerPort(), 1,
                            LoopbackPorts.IPV4_LOOPBACK));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
        }

        void release() throws IOException {
            if (takenPort.isPresent()) {
                takenPort.get().close();
            }
            stop();
        }
    }

    /**
     * Runs only if the build packaged a sandy binary. sandy starts Tor in the level of its check, and Tor exits at
     * once over an invalid torrc entry: no Tor ran in the sandbox, so the status must not say that one does.
     */
    @Test
    void aSandboxedStartWhoseTorExitsBeforeItAnswersReportsNoSandboxedTor() {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "");
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("ConnectionPadding", "invalid"), false, BridgeConfig.NONE, sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).hasMessageContaining("exited before it answered"));

        assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.NOT_STARTED);
        assertThatNoTorOfThisTestRuns();
    }

    /**
     * Runs only if the build packaged a sandy binary. The authorities of a test network listen on 127.0.0.1, which
     * the egress broker of sandy does not reach, so a level with the broker refuses the start before Tor runs. In a
     * level with the network of the host Tor reaches them; these are none.
     */
    @Test
    void aSandboxedStartOfATestNetworkIsRefusedWhereTorReachesOnlyPublicAddresses() {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        DirectoryAuthority authority = DirectoryAuthority.builder()
                .nickname("A0")
                .orPort(1)
                .dirPort(1)
                .v3Ident("0123456789ABCDEF0123456789ABCDEF01234567")
                .relayFingerprint("89ABCDEF0123456789ABCDEF0123456789ABCDEF")
                .build();
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "Turn the sandbox off to test.");
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, true, Set.of(authority), Map.of(), false,
                BridgeConfig.NONE, sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> {
                    Throwable rootCause = Throwables.getRootCause(e);
                    if (rootCause instanceof SandboxUnavailableException) {
                        assertThat(rootCause).hasMessageContaining("directory authorities of the test network")
                                .hasMessageContaining("Turn the sandbox off to test.");
                        assertThat(torService.getSandboxStatus()).isEqualTo(TorSandboxStatus.NOT_STARTED);
                    } else {
                        assertThat(rootCause).isInstanceOf(TorBootstrapFailedException.class);
                        assertThat(torService.getSandboxStatus().isHostNetwork()).isTrue();
                    }
                });
        assertThatNoTorOfThisTestRuns();
    }

    /**
     * Runs only if the build packaged a sandy binary. The egress broker of sandy reaches public addresses only, so a
     * level with the broker refuses bridges which are all on addresses of this host before Tor runs.
     */
    @Test
    void aSandboxedStartWithBridgesOnThisHostIsRefusedWhereTorReachesOnlyPublicAddresses() {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "Turn the sandbox off to test.");
        String bridgeLine = "127.0.0.1:1 0123456789ABCDEF0123456789ABCDEF01234567";
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(), Map.of(), false,
                BridgeConfig.custom(List.of(bridgeLine)), sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> {
                    Throwable rootCause = Throwables.getRootCause(e);
                    if (rootCause instanceof SandboxUnavailableException) {
                        assertThat(rootCause).hasMessageContaining("bridges of the configuration are on addresses")
                                .hasMessageContaining("Turn the sandbox off to test.");
                    } else {
                        assertThat(rootCause).isInstanceOf(TorBootstrapFailedException.class);
                        assertThat(torService.getSandboxStatus().isHostNetwork()).isTrue();
                    }
                });
        assertThatNoTorOfThisTestRuns();
    }

    // In its sandbox Tor connects out only through the egress broker, so a proxy override refuses the start.
    @Test
    void aSandboxedStartRefusesAProxyOfTheTorrcOverrides() {
        assumeBundledTorOfLinux();
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "Turn the sandbox off to test.");
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("HTTPSProxy", "127.0.0.1:1"), false, BridgeConfig.NONE, sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("HTTPSProxy")
                .hasMessageContaining("Turn the sandbox off to test.");
        assertThatNoTorOfThisTestRuns();
    }

    // The default sandbox lets Tor start no process, so a start with transports fails before Tor starts.
    @Test
    void aSandboxedStartRefusesPluggableTransportsUnlessTheConfigurationAllowsThem() throws IOException {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("tor.zip") != null, "The build packaged no Tor bundle");
        assumeTransportProgram(LYREBIRD);
        var sandboxConfig = new TorSandboxConfig(true, true, false, 32, "bisq2", "Turn the sandbox off to test.");
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(), Map.of(), false,
                BridgeConfig.custom(List.of(OBFS4_BRIDGE_ON_A_DOCUMENTATION_ADDRESS)), sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("obfs4")
                .hasMessageContaining("allowPluggableTransports")
                .hasMessageContaining("Turn the sandbox off to test.");
        assertThatNoTorOfThisTestRuns();
    }

    // The sandbox knows only the programs of the configured bridges.
    @Test
    void aSandboxedStartRefusesTransportsOfTheTorrcOverrides() {
        assumeBundledTorOfLinux();
        var overrides = Map.of("UseBridges", "1",
                "Bridge", OBFS4_BRIDGE_ON_A_DOCUMENTATION_ADDRESS,
                "ClientTransportPlugin", "obfs4 exec /bin/false");
        var sandboxConfig = new TorSandboxConfig(true, true, true, 32, "bisq2", "Turn the sandbox off to test.");
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(), overrides, false,
                BridgeConfig.NONE, sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("ClientTransportPlugin")
                .hasMessageContaining("Turn the sandbox off to test.");
        assertThatNoTorOfThisTestRuns();
    }

    // With bridges the overrides of the bridge keys are ignored, but ServerTransportPlugin would stay in the torrc.
    @Test
    void aSandboxedStartWithBridgesRefusesServerTransportsOfTheTorrcOverrides() {
        assumeBundledTorOfLinux();
        var overrides = Map.of("ServerTransportPlugin", "obfs4 exec /bin/false");
        var sandboxConfig = new TorSandboxConfig(true, true, true, 32, "bisq2", "Turn the sandbox off to test.");
        String bridgeLine = "127.0.0.1:1 0123456789ABCDEF0123456789ABCDEF01234567";
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(), overrides, false,
                BridgeConfig.custom(List.of(bridgeLine)), sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .isInstanceOf(SandboxUnavailableException.class)
                .hasMessageContaining("ServerTransportPlugin")
                .hasMessageContaining("Turn the sandbox off to test.");
        assertThatNoTorOfThisTestRuns();
    }

    /**
     * Runs only if the build packaged a sandy binary and the Tor bundle, and lyrebird is in the bundle.
     * obfs4 connects only to the IP address of its bridge, so Tor keeps the network of the sandbox where the host
     * gives one, and the transport connects through the egress broker, which refuses the documentation address.
     */
    @Test
    void aSandboxedStartRunsTheTransportOfTheBridges() throws Exception {
        TorSandboxStatus status = startWithSandboxedTransport(OBFS4_BRIDGE_ON_A_DOCUMENTATION_ADDRESS);

        assertThat(status.getLevel()).isIn("base", "host-network", "host-network-signals");
        String torrc = Files.readString(torDir.resolve("torrc"));
        if (status.isHostNetwork()) {
            assertThat(torrc).doesNotContain("Socks5Proxy");
        } else {
            assertThat(torrc).containsPattern("Socks5Proxy 127\\.0\\.0\\.1:[0-9]+\n");
        }
    }

    // meek_lite resolves the name of its front, which the egress broker does not carry, so Tor gets the host network.
    @Test
    void aSandboxedStartGivesTransportsThatResolveNamesTheNetworkOfTheHost() throws Exception {
        TorSandboxStatus status = startWithSandboxedTransport(
                "meek_lite 192.0.2.20:80 url=https://localhost:1/ front=localhost utls=none");

        assertThat(status.isHostNetwork()).isTrue();
        assertThat(Files.readString(torDir.resolve("torrc"))).doesNotContain("Socks5Proxy");
    }

    /**
     * Starts Tor with the bridge, whose transport cannot reach it, and returns the status of the sandbox after the
     * failed bootstrap. Tor reached its transport in the sandbox, and neither Tor nor the transport is left running.
     */
    private TorSandboxStatus startWithSandboxedTransport(String bridgeLine) throws Exception {
        assumeBundledTorOfLinux();
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        assumeTrue(getClass().getClassLoader().getResource("tor.zip") != null, "The build packaged no Tor bundle");
        assumeTransportProgram(LYREBIRD);
        var sandboxConfig = new TorSandboxConfig(true, true, true, 32, "bisq2", "");
        var transportConfig = new TorTransportConfig(torDir, 10000, 1000, false, Set.of(), Map.of(), false,
                BridgeConfig.custom(List.of(bridgeLine)), sandboxConfig);
        var torService = new TorService(transportConfig, new LocalPlatformServices());
        Instant testStart = Instant.now();

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        TorSandboxStatus status = torService.getSandboxStatus();
        assertThat(status.isSandboxed()).isTrue();
        assertThat(Files.readString(torDir.resolve("tor.log"))).contains("Connected to pluggable transport");
        assertThatNoTorOfThisTestRuns();
        assertThatNoTransportStartedSince(testStart);
        return status;
    }

    /**
     * The program of the transport is found by its name. The start time keeps out transports of other programs which run
     * on this host.
     */
    private static void assertThatNoTransportStartedSince(Instant start) {
        assertThat(ProcessHandle.allProcesses()
                .filter(ProcessHandle::isAlive)
                .filter(process -> process.info().startInstant().filter(started -> !started.isBefore(start)).isPresent())
                .flatMap(process -> process.info().command().stream())
                .anyMatch(command -> Paths.get(command).getFileName().toString().equals(LYREBIRD)))
                .isFalse();
    }

    /**
     * Skips the test unless the Tor bundle has the program of a pluggable transport. The check reads tor.zip itself
     * instead of using the lookup of TorService, so that a lookup which misses a bundled program fails the test instead
     * of skipping it.
     */
    private void assumeTransportProgram(String programName) throws IOException {
        assumeTrue(isInTorBundle(programName), "No " + programName + " in the Tor bundle");
    }

    // The tests check the start on Linux, with its sandbox levels.
    private void assumeBundledTorOfLinux() {
        assumeTrue(OS.isLinux(), "The test checks the start on Linux");
        assumeTrue(getClass().getClassLoader().getResource("tor.zip") != null, "The build packaged no Tor bundle");
    }

    private boolean isInTorBundle(String programName) throws IOException {
        URL torBundle = getClass().getClassLoader().getResource("tor.zip");
        if (torBundle == null) {
            return false;
        }
        String entryName = TorDirectories.PLUGGABLE_TRANSPORTS_DIR_NAME + "/" + programName;
        try (ZipInputStream zip = new ZipInputStream(torBundle.openStream())) {
            for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                if (entry.getName().equals(entryName)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Test
    void aStartWithBridgesConnectsOnlyToTheBridges() throws Exception {
        assumeBundledTorOfLinux();
        // A bridge without pluggable transport on a closed local port. With UseBridges, Tor connects to no other
        // relay, so it cannot bootstrap.
        String bridgeLine = "127.0.0.1:1 0123456789ABCDEF0123456789ABCDEF01234567";
        var transportConfig = new TorTransportConfig(torDir, 3000, 1000, false, Set.of(),
                Map.of("UseBridges", "0"), false, BridgeConfig.custom(List.of(bridgeLine)));
        var torService = new TorService(transportConfig, new LocalPlatformServices());

        assertThatThrownBy(() -> torService.initialize())
                .satisfies(e -> assertThat(Throwables.getRootCause(e)).isInstanceOf(TorBootstrapFailedException.class));

        // Tor accepted the bridge entries. The override of UseBridges is ignored.
        String torrc = Files.readString(torDir.resolve("torrc"));
        assertThat(torrc).contains("UseBridges 1\n", "Bridge " + bridgeLine + "\n").doesNotContain("UseBridges 0");
        assertThatNoTorOfThisTestRuns();
    }

    private void assertThatNoTorOfThisTestRuns() {
        assertThatNoTorOfThisTestRuns(torDir);
    }

    private static void assertThatNoTorOfThisTestRuns(Path torDir) {
        // The check needs the arguments of the other processes. Where the JDK cannot read them, for example on a
        // hardened kernel, the check would pass without having seen a Tor process.
        assumeTrue(ProcessHandle.current().info().arguments().isPresent(),
                "The JDK cannot read the arguments of processes here");
        String torrcPath = torDir.resolve("torrc").toAbsolutePath().toString();
        assertThat(ProcessHandle.allProcesses()
                .filter(ProcessHandle::isAlive)
                .flatMap(process -> process.info().arguments().stream())
                .anyMatch(arguments -> Stream.of(arguments).anyMatch(torrcPath::equals)))
                .isFalse();
    }

    private static class LocalPlatformServices implements PlatformServices {
        @Override
        public String getMyPid() {
            return String.valueOf(ProcessHandle.current().pid());
        }

        @Override
        public Stream<String> getProcessCommandStream() {
            return ProcessHandle.allProcesses().map(process -> process.info().command().orElse(""));
        }

        @Override
        public boolean supportsPosixPermissions() {
            return true;
        }
    }
}
