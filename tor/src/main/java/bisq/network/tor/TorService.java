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

import bisq.network.tor.bridges.BridgeTorrcEntries;
import bisq.network.tor.bridges.PluggableTransportConfig;
import bisq.network.tor.bridges.PluggableTransportPrograms;
import bisq.network.tor.common.file.FileUtils;
import bisq.network.tor.common.platform.LinuxDistribution;
import bisq.network.tor.common.platform.OS;
import bisq.network.tor.common.platform.Platform;
import bisq.network.tor.common.torrc.DirectoryAuthority;
import bisq.network.tor.common.torrc.TorrcFileGenerator;
import bisq.network.tor.common.torrc.TorrcSyntax;
import bisq.network.tor.controller.PasswordDigest;
import bisq.network.tor.controller.TorCommandFilteredException;
import bisq.network.tor.controller.TorControlAuthenticationFailed;
import bisq.network.tor.controller.TorController;
import bisq.network.tor.installer.TorBinaryZipExtractor;
import bisq.network.tor.installer.TorInstaller;
import bisq.network.tor.onionservice.DirectOnionServiceTargets;
import bisq.network.tor.onionservice.ForwardedOnionServiceTargets;
import bisq.network.tor.onionservice.OnionServiceKey;
import bisq.network.tor.onionservice.OnionServiceTargets;
import bisq.network.tor.process.ControlPortProbe;
import bisq.network.tor.process.BundledTorLibraries;
import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.LoopbackPorts;
import bisq.network.tor.process.TorDataDirectoryMode;
import bisq.network.tor.process.TorDirectories;
import bisq.network.tor.process.TorDirectoryMigration;
import bisq.network.tor.process.TorListenerPorts;
import bisq.network.tor.process.TorListenerPorts.PortMapping;
import bisq.network.tor.process.TorStartupFailedException;
import bisq.network.tor.sandbox.EgressReach;
import bisq.network.tor.sandbox.PluggableTransportsNotAllowedException;
import bisq.network.tor.sandbox.SandboxUnavailableException;
import bisq.network.tor.sandbox.SandboxedTransports;
import bisq.network.tor.sandbox.Sandy;
import bisq.network.tor.sandbox.SandyBinary;
import bisq.network.tor.sandbox.SandyPolicy;
import bisq.network.tor.sandbox.SandyStatusRecord;
import bisq.network.tor.sandbox.TorMemoryLimit;
import bisq.network.tor.sandbox.TorSandboxPolicy;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.InetAddresses;
import com.runjva.sourceforge.jsocks.protocol.Socks5Proxy;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;


@Slf4j
public class TorService {
    private static final long CONTROL_PORT_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(30);
    private static final long CONTROL_PORT_POLL_INTERVAL_MS = 100;
    private static final String GEOIP_FILE = "GeoIPFile";
    private static final int AUTH_COOKIE_LENGTH = 32;
    private static final String GEOIP_V6_FILE = "GeoIPv6File";
    private static final String SOCKS5_PROXY = "Socks5Proxy";
    private static final String MAX_MEM_IN_QUEUES = "MaxMemInQueues";
    private static final int STATUS_DLL_INIT_FAILED = 0xC0000142;
    // sandy and the Tor which it runs write the standard error of a sandboxed start, and Tor can rewrite the file, so a
    // quote of it can be the text of a compromised Tor.
    private static final String SANDBOXED_STDERR_LABEL =
            "stderr (written by sandy and by Tor in its sandbox, not verified by Bisq)";
    // Environment variable to not launch the embedded Tor process
    public static final String TOR_SKIP_LAUNCH = "TOR_SKIP_LAUNCH";

    private final TorTransportConfig transportConfig;
    private final PlatformServices platformServices;
    private final TorDirectories torDirectories;
    // On Whonix, Bisq uses the Tor of the Whonix-Gateway through onion-grater.
    private final boolean isWhonix;
    // On the Whonix-Gateway itself, Bisq does not start.
    private final boolean isWhonixGateway;
    // Creates the controller of each start, see createControllerOfTheStart
    private final Supplier<TorController> torControllerFactory;

    private final Object lifecycleLock = new Object();
    // The initialization which runs or succeeded, whose result every caller of initialize gets. Empty before the first
    // initialization, after a failed one, and from the begin of a shutdown on. Guarded by lifecycleLock.
    private Optional<CompletableFuture<Boolean>> initialization = Optional.empty();
    // The shutdown which runs. Guarded by lifecycleLock.
    private Optional<CompletableFuture<Boolean>> runningShutdown = Optional.empty();

    // Written by initialize and by shutdown, which runs on another thread, and read by the API methods
    private volatile TorController torController;
    // Written by initialize, read by the user interface
    @Getter
    private volatile boolean useExternalTor;
    // The version which the running Tor reports
    @Getter
    private volatile Optional<String> torVersion = Optional.empty();
    // Whether the Tor of this start runs in the sandbox, for the user interface
    @Getter
    private volatile TorSandboxStatus sandboxStatus = TorSandboxStatus.NOT_STARTED;

    private volatile Optional<EmbeddedTorProcess> torProcess = Optional.empty();
    private volatile Optional<TorSocksProxyFactory> torSocksProxyFactory = Optional.empty();
    private volatile OnionServiceTargets onionServiceTargets = new DirectOnionServiceTargets(LoopbackPorts.IPV4_LOOPBACK);

    public TorService(TorTransportConfig transportConfig, PlatformServices platformServices) {
        this(transportConfig, platformServices, LinuxDistribution.isWhonix(), LinuxDistribution.isWhonixGateway());
    }

    @VisibleForTesting
    TorService(TorTransportConfig transportConfig, PlatformServices platformServices, boolean isWhonix) {
        this(transportConfig, platformServices, isWhonix, false);
    }

    @VisibleForTesting
    TorService(TorTransportConfig transportConfig,
               PlatformServices platformServices,
               boolean isWhonix,
               boolean isWhonixGateway) {
        this(transportConfig, platformServices, isWhonix, isWhonixGateway,
                () -> new TorController(transportConfig.getBootstrapTimeout(), transportConfig.getHsUploadTimeout(),
                        isWhonix));
    }

    @VisibleForTesting
    TorService(TorTransportConfig transportConfig,
               PlatformServices platformServices,
               boolean isWhonix,
               Supplier<TorController> torControllerFactory) {
        this(transportConfig, platformServices, isWhonix, false, torControllerFactory);
    }

    private TorService(TorTransportConfig transportConfig,
                       PlatformServices platformServices,
                       boolean isWhonix,
                       boolean isWhonixGateway,
                       Supplier<TorController> torControllerFactory) {
        this.transportConfig = transportConfig;
        this.platformServices = platformServices;
        this.torDirectories = new TorDirectories(transportConfig.getDataDirPath());
        this.isWhonix = isWhonix;
        this.isWhonixGateway = isWhonixGateway;
        this.torControllerFactory = () -> createControllerOfTheStart(torControllerFactory);
    }

    /**
     * Starts Tor, or connects to the external Tor, in the thread of the caller. Callers share one initialization: a
     * call while it runs gets its result, and a call after its success gets the success at once. A failure lets the
     * next call start again, also a failure before the connection, for example an invalid external_tor.config. A
     * shutdown while the initialization runs makes it fail. A call during a shutdown waits for the end of the shutdown
     * and then starts again, as a call after a shutdown does.
     *
     * @return a future which completes with true once Tor runs. The caller whose thread runs the start gets a failure
     * thrown; the callers which share the initialization get it in the future.
     */
    public CompletableFuture<Boolean> initialize() {
        CompletableFuture<Boolean> ownInitialization = new CompletableFuture<>();
        Optional<CompletableFuture<Boolean>> sharedInitialization = shareOrBeginInitialization(ownInitialization);
        if (sharedInitialization.isPresent()) {
            return sharedInitialization.get();
        }
        try {
            start();
        } catch (RuntimeException | Error e) {
            synchronized (lifecycleLock) {
                if (isCurrentInitialization(ownInitialization)) {
                    initialization = Optional.empty();
                }
            }
            ownInitialization.completeExceptionally(e);
            throw e;
        }
        boolean isEndedByShutdown;
        synchronized (lifecycleLock) {
            isEndedByShutdown = !isCurrentInitialization(ownInitialization);
        }
        if (isEndedByShutdown) {
            // The shutdown stops what this start created once the future has completed.
            TorStartupFailedException failure = shutDownDuringTheStart();
            ownInitialization.completeExceptionally(failure);
            throw failure;
        }
        ownInitialization.complete(true);
        return ownInitialization;
    }

    // An initialization runs after a running shutdown has ended, never alongside it.
    private Optional<CompletableFuture<Boolean>> shareOrBeginInitialization(CompletableFuture<Boolean> ownInitialization) {
        while (true) {
            CompletableFuture<Boolean> shutdown;
            synchronized (lifecycleLock) {
                if (runningShutdown.isEmpty()) {
                    if (initialization.isPresent()) {
                        return initialization;
                    }
                    initialization = Optional.of(ownInitialization);
                    return Optional.empty();
                }
                shutdown = runningShutdown.get();
            }
            shutdown.handle((result, throwable) -> result).join();
        }
    }

    // Only a shutdown replaces the initialization of a running start.
    private boolean isCurrentInitialization(CompletableFuture<Boolean> ownInitialization) {
        return initialization.isPresent() && initialization.get() == ownInitialization;
    }

    /**
     * A start creates its controller only while no shutdown has ended its initialization. A shutdown before the start
     * had a controller shuts down none of this start, so the start would otherwise start Tor after the shutdown.
     */
    private TorController createControllerOfTheStart(Supplier<TorController> factory) {
        TorController controller = factory.get();
        synchronized (lifecycleLock) {
            if (initialization.isPresent()) {
                return controller;
            }
        }
        runQuietly(controller::shutdown, "Shutdown of the Tor controller failed");
        throw shutDownDuringTheStart();
    }

    private static TorStartupFailedException shutDownDuringTheStart() {
        return new TorStartupFailedException("The Tor service was shut down during its start");
    }

    private void start() {
        refuseWhonixGateway();
        // A failed start before may have left the status of its Tor, which does not run.
        sandboxStatus = TorSandboxStatus.NOT_STARTED;
        makeTorDir();

        ExternalTorConfig externalTorConfig = readExternalTorConfig();

        useExternalTor = evaluateUseExternalTor(externalTorConfig);
        if (useExternalTor) {
            sandboxStatus = TorSandboxStatus.EXTERNAL_TOR;
            log.info(sandboxStatus.getDescription());
            if (transportConfig.getBridgeConfig().isUsed()) {
                log.warn("Bisq does not use the bridges of its configuration, because it uses an external Tor. The " +
                        "external Tor uses the bridges of its own configuration.");
            }
            try {
                connectToExternalTor(externalTorConfig);
            } catch (RuntimeException e) {
                // The user may rely on the external Tor, for example for its bridges or for the Tor of Whonix. An own
                // Tor would connect directly to the Tor network instead, so the start fails.
                if (torController != null) {
                    runQuietly(torController::shutdown, "Shutdown of the Tor controller failed");
                    torController = null;
                }
                // Without the cause: Bisq 2 shows only the root cause of a failed start, and this exception has to be
                // it, so that the user sees the explanation and the hint.
                log.warn("Bisq cannot use the external Tor", e);
                throw new ExternalTorUnavailableException(getExternalTorUnavailableMessage(externalTorConfig, e));
            }
            log.info("External Tor will be used");
            return;
        }

        try {
            startEmbeddedTor();
        } catch (RuntimeException e) {
            // The reserved server sockets of the onion services are of no use without Tor.
            onionServiceTargets.close();
            throw e;
        }
    }

    /**
     * Bisq chooses the ports of the sandbox policy and releases them before sandy binds them, so another process can
     * take one in between. sandy then refuses the start with status 125 before Tor runs: sandy check, which tries the
     * ports, because it cannot tell now, and sandy run because it cannot listen on the port. Such a refusal can pass,
     * so the start runs once more, with new ports. A second refusal fails the start with the advice to turn the
     * sandbox off.
     */
    private void startEmbeddedTor() {
        retryOnceAfterARefusalOfSandy(this::startEmbeddedTorOnce);
    }

    @VisibleForTesting
    static void retryOnceAfterARefusalOfSandy(Runnable start) {
        try {
            start.run();
        } catch (SandyRefusalException e) {
            log.warn("sandy refused to start Tor. Bisq tries once more with other ports, in case another process " +
                    "took one of them. {}", e.getReason());
            start.run();
        }
    }

    /**
     * sandy refused a start with status 125 before Tor ran. Unlike a system which enforces no level of the sandbox,
     * this can pass, for example when another process held a port of the policy.
     */
    @VisibleForTesting
    static final class SandyRefusalException extends SandboxUnavailableException {
        @Getter
        private final String reason;

        SandyRefusalException(String reason, String optOutHint) {
            super(reason, optOutHint);
            this.reason = reason;
        }
    }

    private void startEmbeddedTorOnce() {
        boolean isNewDataDirectory = prepareTorDirectories();
        installTorIfNotUpToDate();

        Path torBinaryPath = torDirectories.getBundledTorBinaryPath();

        if (torController != null) {
            torController.shutdown();
        }
        torController = torControllerFactory.get();

        BridgeConfig bridgeConfig = transportConfig.getBridgeConfig();
        List<Map.Entry<String, String>> bridgeEntries = bridgeConfig.isUsed() ?
                createBridgeTorrcEntries(bridgeConfig) :
                List.of();
        TorSandboxConfig sandboxConfig = transportConfig.getSandboxConfig();
        SandboxedTransports transports = createSandboxedTransports(bridgeEntries);
        boolean isSandboxed = isSandboxed(sandboxConfig);
        if (isSandboxed) {
            refuseWhatTheSandboxCannotRun(sandboxConfig, bridgeConfig, transports);
        }

        TorListenerPorts listenerPorts = reservePorts(isSandboxed, sandboxConfig.getOnionServicePortPoolSize());
        PasswordDigest hashedControlPassword = PasswordDigest.generateDigest();
        createEmptyOpenSslConfig();

        EmbeddedTorProcess embeddedTorProcess;
        Optional<Sandy.Level> sandboxLevel;
        Optional<SandboxedRun> sandboxedRun;
        if (isSandboxed) {
            // The policy names the torrc, which must exist when sandy checks the policy. Tor reads the torrc written
            // after the check, for the level which sandy selected.
            createTorrcConfigFile(hashedControlPassword, listenerPorts, bridgeEntries, true, OptionalInt.empty());
            SandboxedStart sandboxedStart = checkSandbox(torBinaryPath, listenerPorts, sandboxConfig, transports);
            refuseDestinationsOutsideTheEgress(sandboxedStart.level(), transportConfig.getDirectoryAuthorities(),
                    bridgeEntries, sandboxConfig.getOptOutHint());
            createTorrcConfigFile(hashedControlPassword, listenerPorts, bridgeEntries, true,
                    sandboxedStart.socks5ProxyPort(listenerPorts));
            embeddedTorProcess = createSandboxedTorProcess(torBinaryPath, sandboxedStart);
            sandboxLevel = Optional.of(sandboxedStart.level());
            sandboxedRun = Optional.of(new SandboxedRun(torDirectories.getSandyStatusRecordPath(),
                    Sandy.staysParent(OS.getOS(), sandboxedStart.level()), sandboxConfig.getOptOutHint()));
        } else {
            createTorrcConfigFile(hashedControlPassword, listenerPorts, bridgeEntries, false, OptionalInt.empty());
            embeddedTorProcess = createTorProcess(torBinaryPath);
            sandboxLevel = Optional.empty();
            sandboxedRun = Optional.empty();
        }
        prepareDataDirectory(isSandboxed, isNewDataDirectory);
        torProcess = Optional.of(embeddedTorProcess);

        int controlPort = listenerPorts.control().outerPort();
        try {
            // Inside the try, so that a failed start also stops the process and releases the ports.
            embeddedTorProcess.start();
            waitUntilControlPortAnswers(controlPort, embeddedTorProcess, sandboxedRun);

            torController.initialize(controlPort);
            torController.authenticate(hashedControlPassword);
            // Bisq released the chosen ports before Tor bound them. Before Bisq sends any secret (the onion service
            // keys), it checks that the process on the port is the Tor of this start.
            torController.verifyHashedControlPassword(hashedControlPassword);
            // Only now is it known that sandy started the Tor of this start in the level of the check.
            sandboxLevel.ifPresent(this::reportSandboxLevel);
            torController.bootstrap();
            if (!embeddedTorProcess.isAlive()) {
                throw new TorStartupFailedException("Embedded Tor exited during bootstrap. " +
                        startupDiagnostics(embeddedTorProcess, sandboxedRun.isPresent()));
            }
            // Tor binds its SOCKS port only when the bootstrap enables the network, seconds after Bisq released it.
            verifySocksListener(listenerPorts.socks().innerPort());

            torVersion = torController.getTorVersion();
            log.info("Tor {} runs with the binary {}", torVersion.orElse("of unknown version"), torBinaryPath);

            torSocksProxyFactory = Optional.of(new TorSocksProxyFactory(listenerPorts.socks().outerPort()));
        } catch (InterruptedException e) {
            stopEmbeddedTor(embeddedTorProcess);
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting for the tor control port", e);
        } catch (IOException e) {
            stopEmbeddedTor(embeddedTorProcess);
            throw new RuntimeException("Error while waiting for the tor control port", e);
        } catch (RuntimeException e) {
            stopEmbeddedTor(embeddedTorProcess);
            throw e;
        }
    }

    // Tor runs in the sandbox if the configuration turns it on.
    private boolean isSandboxed(TorSandboxConfig sandboxConfig) {
        if (sandboxConfig.isEnabled()) {
            return true;
        }
        sandboxStatus = TorSandboxStatus.DISABLED;
        log.info(sandboxStatus.getDescription());
        return false;
    }

    /**
     * In its sandbox Tor has a network of its own, so it reaches the onion services of Bisq only through ports which
     * sandy forwards, and it connects out only through sandy's egress broker, which Bisq sets as its proxy. It may
     * start only the pluggable transports of the configured bridges, and those only if the configuration allows them.
     */
    @VisibleForTesting
    void refuseWhatTheSandboxCannotRun(TorSandboxConfig sandboxConfig,
                                       BridgeConfig bridgeConfig,
                                       SandboxedTransports transports) {
        if (!sandboxConfig.isForwardOnionServicePorts()) {
            throw new SandboxUnavailableException("Tor in the sandbox reaches the onion services of Bisq only " +
                    "through forwarded ports, but forwardOnionServicePorts of the sandbox is false.",
                    sandboxConfig.getOptOutHint());
        }
        List<String> proxyKeys = TorrcClientConfigFactory.proxyKeys(transportConfig.getTorrcOverrides().keySet());
        if (!proxyKeys.isEmpty()) {
            throw new SandboxUnavailableException("The torrc overrides set " + String.join(", ", proxyKeys) +
                    ". In its sandbox Tor connects out only through the egress broker of sandy, which Bisq sets as " +
                    "its proxy. Remove these overrides to run Tor in the sandbox.", sandboxConfig.getOptOutHint());
        }
        // Tor reads the value as a file name, with quotes, "~" and paths relative to its working directory, so a
        // grant of the path could miss the file which Tor opens. Its country selectors would then match no relay.
        List<String> geoIpFileKeys = TorrcClientConfigFactory.geoIpFileKeys(transportConfig.getTorrcOverrides().keySet());
        if (!geoIpFileKeys.isEmpty()) {
            throw new SandboxUnavailableException("The torrc overrides set " + String.join(", ", geoIpFileKeys) +
                    ", but in its sandbox Tor reads only the GeoIP files of its installation. Remove these overrides " +
                    "to run Tor in the sandbox.", sandboxConfig.getOptOutHint());
        }
        List<String> processStartingKeys = TorrcClientConfigFactory.processStartingKeys(
                transportConfig.getTorrcOverrides().keySet(), bridgeConfig.isUsed());
        if (!processStartingKeys.isEmpty()) {
            throw new SandboxUnavailableException("The torrc overrides set " + String.join(", ", processStartingKeys) +
                    ", which make Tor start programs that its sandbox does not know. Remove these overrides; to use " +
                    "pluggable transports in the sandbox, configure bridges.", sandboxConfig.getOptOutHint());
        }
        if (!transports.isEmpty() && !sandboxConfig.isAllowPluggableTransports()) {
            List<String> transportNames = transports.transportNames().stream().sorted().toList();
            throw new PluggableTransportsNotAllowedException("The bridges use the pluggable transports " +
                    String.join(", ", transportNames) + ", programs which Tor starts. Its sandbox lets Tor start " +
                    "them only if allowPluggableTransports of the sandbox configuration is true.",
                    sandboxConfig.getOptOutHint(), transportNames);
        }
    }

    /**
     * In a level with the egress broker, Tor connects out only through the broker of sandy, which reaches public
     * addresses only (reach = "public" of the templates). A destination on an address of this host or of the local
     * network would fail only at the bootstrap timeout, without a word about the sandbox.
     */
    @VisibleForTesting
    static void refuseDestinationsOutsideTheEgress(Sandy.Level level,
                                                   Set<DirectoryAuthority> directoryAuthorities,
                                                   List<Map.Entry<String, String>> bridgeEntries,
                                                   String optOutHint) {
        if (!level.enforces(Sandy.EGRESS_BROKERED)) {
            return;
        }
        String egress = "In the level " + level.name() + " of its sandbox Tor connects out only through the egress " +
                "broker of sandy, which reaches public addresses only.";
        if (!directoryAuthorities.isEmpty()) {
            throw new SandboxUnavailableException("The directory authorities of the test network listen on " +
                    "127.0.0.1, an address of this host. " + egress, optOutHint);
        }
        // Tor uses every bridge it reaches. The addresses are not named: a private bridge is blocked once it is known.
        List<String> bridgeLines = bridgeEntries.stream()
                .filter(entry -> entry.getKey().equals(BridgeTorrcEntries.BRIDGE))
                .map(Map.Entry::getValue)
                .toList();
        long unreachableBridges = bridgeLines.stream()
                .filter(line -> BridgeTorrcEntries.findAddress(line).filter(EgressReach::isOfThisHostOrLocalNetwork)
                        .isPresent())
                .count();
        if (unreachableBridges > 0 && unreachableBridges == bridgeLines.size()) {
            throw new SandboxUnavailableException("The bridges of the configuration are on addresses of this host " +
                    "or of the local network. " + egress, optOutHint);
        }
        if (unreachableBridges > 0) {
            log.warn("{} of the {} bridges are on addresses of this host or of the local network, which Tor cannot " +
                    "reach in its sandbox. {}", unreachableBridges, bridgeLines.size(), egress);
        }
    }

    // The pluggable transports of the bridges, with the absolute paths of their programs
    private SandboxedTransports createSandboxedTransports(List<Map.Entry<String, String>> bridgeEntries) {
        List<BridgeTorrcEntries.ClientTransportPlugin> plugins =
                BridgeTorrcEntries.findClientTransportPlugins(bridgeEntries);
        Set<String> transportNames = plugins.stream()
                .flatMap(plugin -> plugin.transports().stream())
                .collect(Collectors.toSet());
        // A bundled program is relative to the binary directory, the working directory of Tor.
        List<Path> programPaths = plugins.stream()
                .map(plugin -> torDirectories.getBinaryDirPath().resolve(plugin.program()).toAbsolutePath().normalize())
                .distinct()
                .toList();
        return new SandboxedTransports(transportNames, programPaths);
    }

    /**
     * Chooses the ports of the control and SOCKS listeners, and creates the targets of the onion services. In the
     * sandbox it also chooses the port of the egress broker and reserves the pool of forwarded onion service ports.
     */
    private TorListenerPorts reservePorts(boolean isSandboxed, int onionServicePortPoolSize) {
        try {
            onionServiceTargets.close();
            if (isSandboxed) {
                ForwardedOnionServiceTargets.Reservation reservation = ForwardedOnionServiceTargets.reserve(
                        onionServicePortPoolSize, 5, "onionServicePortPoolSize of the Tor sandbox");
                onionServiceTargets = reservation.targets();
                List<Integer> ports = reservation.listenerPorts();
                TorListenerPorts listenerPorts = new TorListenerPorts(new PortMapping(ports.get(0), ports.get(1)),
                        new PortMapping(ports.get(2), ports.get(3)),
                        OptionalInt.of(ports.get(4)));
                log.info("Tor listener ports: {}", listenerPorts);
                return listenerPorts;
            }
            List<Integer> ports = LoopbackPorts.allocate(2);
            onionServiceTargets = new DirectOnionServiceTargets(LoopbackPorts.IPV4_LOOPBACK);
            TorListenerPorts listenerPorts = new TorListenerPorts(new PortMapping(ports.get(0), ports.get(0)),
                    new PortMapping(ports.get(1), ports.get(1)));
            log.info("Tor listener ports: {}", listenerPorts);
            return listenerPorts;
        } catch (IOException e) {
            log.warn("Couldn't reserve the ports of Tor", e);
            throw new TorStartupFailedException("Couldn't reserve the loopback ports of Tor: " + e);
        }
    }

    /**
     * The policy of this start, sandy, and the level of the policy that sandy selected for this host.
     */
    private record SandboxedStart(Sandy sandy, SandyPolicy policy, Sandy.Level level) {
        // Tor connects out through the egress broker of sandy in the levels which have one.
        OptionalInt socks5ProxyPort(TorListenerPorts listenerPorts) {
            return level.enforces(Sandy.EGRESS_BROKERED) ? listenerPorts.egress() : OptionalInt.empty();
        }
    }

    /**
     * What tells a refusal of sandy from an exit of Tor: the status record of the run, and whether sandy stays the
     * parent of Tor in its level ({@link Sandy#endedBeforeTheProgramRan}). The opt-out hint is for a refusal.
     */
    @VisibleForTesting
    record SandboxedRun(Path statusRecordPath, boolean staysParent, String optOutHint) {
    }

    private SandboxedStart checkSandbox(Path torBinaryPath,
                                        TorListenerPorts listenerPorts,
                                        TorSandboxConfig sandboxConfig,
                                        SandboxedTransports transports) {
        String optOutHint = sandboxConfig.getOptOutHint();
        // Outside the try: a Tor directory whose libraries the loader cannot find fails the start without the sandbox
        // too, so its failure is no refusal of the sandbox.
        Map<String, String> torEnvironment = sandboxedTorEnvironment(torDirectories);
        try {
            OS os = OS.getOS();
            SandyPolicy policy = TorSandboxPolicy.create(os,
                    torDirectories,
                    listenerPorts,
                    toForwardedPorts(onionServiceTargets),
                    torEnvironment,
                    TorSandboxPolicy.executablePaths(os, torDirectories),
                    transports,
                    sandboxConfig.getApplicationId());
            Sandy sandy = new Sandy(SandyBinary.install(torDirectories.getSandyDirPath(), Platform.getPlatform()),
                    platformServices.getMyPid());
            Sandy.CheckResult checkResult = sandy.check(policy, torBinaryPath);
            Sandy.Level level = checkResult.selectedLevel()
                    .orElseThrow(() -> refusalOfCheck(checkResult, optOutHint));
            log.info("sandy selected the level {} of the sandbox of Tor. sandy check:\n{}", level.name(),
                    checkResult.report());
            return new SandboxedStart(sandy, policy, level);
        } catch (SandboxUnavailableException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            // Without the cause: Bisq 2 shows only the root cause of a failed start, and this exception has to be it,
            // so that the user sees the reason and the hint.
            log.warn("Tor cannot run in the sandbox", e);
            throw new SandboxUnavailableException(e.getMessage(), optOutHint);
        }
    }

    private void reportSandboxLevel(Sandy.Level level) {
        sandboxStatus = TorSandboxStatus.sandboxed(level.name(),
                level.enforces(Sandy.IP_NETWORK_PRIVATE),
                level.enforces(Sandy.SIGNALS_ISOLATED));
        log.info("Tor runs in the level {} of its sandbox", level.name());
        if (sandboxStatus.isHostNetwork() || sandboxStatus.isSignalsNotIsolated()) {
            log.warn(sandboxStatus.getDescription());
        }
    }

    // Status 125: sandy cannot tell now, for example because another process holds a port of the policy.
    @VisibleForTesting
    static SandboxUnavailableException refusalOfCheck(Sandy.CheckResult checkResult, String optOutHint) {
        String reason = describeRefusal(checkResult);
        return checkResult.exitCode() == Sandy.EXIT_STATUS_NOT_STARTED ?
                new SandyRefusalException(reason, optOutHint) :
                new SandboxUnavailableException(reason, optOutHint);
    }

    private static String describeRefusal(Sandy.CheckResult checkResult) {
        String reason = switch (checkResult.exitCode()) {
            case 1, 2 -> "This system cannot enforce any level of the sandbox of Tor.";
            case Sandy.EXIT_STATUS_NOT_STARTED -> "sandy cannot tell now whether this system enforces the sandbox " +
                    "of Tor, or the policy conflicts with this system. A later start may succeed.";
            default -> "sandy check failed with exit code " + checkResult.exitCode() + ".";
        };
        return reason + "\n" + checkResult.report();
    }

    private EmbeddedTorProcess createSandboxedTorProcess(Path torBinaryPath, SandboxedStart sandboxedStart) {
        Path statusRecordPath = torDirectories.getSandyStatusRecordPath();
        // sandy refuses a path which exists, and Bisq would then read the record of an earlier run.
        try {
            Files.deleteIfExists(statusRecordPath);
        } catch (IOException e) {
            log.warn("Couldn't remove the status record of an earlier run of sandy", e);
            throw new TorStartupFailedException("Couldn't remove the status record of an earlier run of sandy " +
                    statusRecordPath + ": " + e);
        }
        return new EmbeddedTorProcess(sandboxedStart.sandy().runCommand(sandboxedStart.policy(),
                sandboxedStart.level(),
                statusRecordPath,
                sandboxedTorCommand(torBinaryPath, torDirectories.getTorrcPath(), sandboxedStart.level(),
                        platformServices.getMyPid())),
                torDirectories.getBinaryDirPath(),
                Sandy::removeLoaderVariables,
                torDirectories.getStdoutLogPath(),
                torDirectories.getStderrLogPath(),
                Optional.of(Sandy.policyInput(sandboxedStart.policy())));
    }

    // In the sandbox, Tor gets only this environment.
    @VisibleForTesting
    static Map<String, String> sandboxedTorEnvironment(TorDirectories torDirectories) {
        Map<String, String> environment =
                new HashMap<>(BundledTorLibraries.environment(torDirectories.getBinaryDirPath()));
        environment.put("OPENSSL_CONF", torDirectories.getOpenSslConfigPath().toAbsolutePath().toString());
        return environment;
    }

    private static List<SandyPolicy.ForwardedPort> toForwardedPorts(OnionServiceTargets onionServiceTargets) {
        if (onionServiceTargets instanceof ForwardedOnionServiceTargets forwardedOnionServiceTargets) {
            return forwardedOnionServiceTargets.getPortPairs().stream()
                    .map(pair -> new SandyPolicy.ForwardedPort(pair.innerPort(), pair.outerPort()))
                    .collect(Collectors.toList());
        }
        return List.of();
    }

    private void verifySocksListener(int socksPort) {
        int reportedSocksPort = torController.getSocksPort();
        if (reportedSocksPort != socksPort) {
            throw new TorStartupFailedException("Tor reports its SOCKS listener on port " + reportedSocksPort +
                    " instead of the chosen port " + socksPort + ". Another process may listen on the chosen port.");
        }
    }

    private EmbeddedTorProcess createTorProcess(Path torBinaryPath) {
        Consumer<Map<String, String>> environmentAdjuster = environment -> {
            BundledTorLibraries.applyToEnvironment(environment, torDirectories.getBinaryDirPath());
            // The OpenSSL of the bundled Tor reads openssl.cnf from a directory of its build below /var/tmp/dist, where
            // any local user can create files, unless OPENSSL_CONF names another file. The configuration can load
            // modules into Tor.
            environment.put("OPENSSL_CONF", torDirectories.getOpenSslConfigPath().toAbsolutePath().toString());
        };
        return new EmbeddedTorProcess(createTorCommand(torBinaryPath),
                torDirectories.getBinaryDirPath(),
                environmentAdjuster,
                torDirectories.getStdoutLogPath(),
                torDirectories.getStderrLogPath());
    }

    private List<String> createTorCommand(Path torBinaryPath) {
        String ownerPid = platformServices.getMyPid();
        return EmbeddedTorProcess.torCommand(torBinaryPath, torDirectories.getTorrcPath(), ownerPid);
    }

    /**
     * In a level that ends with its parent, sandy ends Tor when Bisq ends, so Tor gets no owner process. Its own check
     * of the owner would fail where Tor runs in a PID namespace of its own (the Linux level contained and the base
     * levels of the Linux transport templates): Bisq's process ID does not exist there, so Tor exits at its first
     * check, about 15 seconds after its start, unless the bootstrap has reset the option before. In the templates, a
     * level without end_with_parent has no PID namespace, so the owner check works there.
     */
    @VisibleForTesting
    static List<String> sandboxedTorCommand(Path torBinaryPath, Path torrcPath, Sandy.Level level, String ownerPid) {
        return level.enforces(Sandy.ENDS_WITH_PARENT) ?
                EmbeddedTorProcess.torCommand(torBinaryPath, torrcPath) :
                EmbeddedTorProcess.torCommand(torBinaryPath, torrcPath, ownerPid);
    }

    private void stopEmbeddedTor(EmbeddedTorProcess embeddedTorProcess) {
        if (torController != null) {
            runQuietly(torController::shutdown, "Shutdown of the Tor controller failed");
        }
        embeddedTorProcess.shutdown();
        torProcess = Optional.empty();
        onionServiceTargets.close();
    }

    private static void runQuietly(Runnable runnable, String errorMessage) {
        try {
            runnable.run();
        } catch (RuntimeException e) {
            log.warn(errorMessage, e);
        }
    }

    // With CookieAuthentication, Bisq only uses SAFECOOKIE: Tor proves that it knows the cookie before Bisq sends
    // anything else. A process which listens on the port instead of Tor gets no secret. Bisq never falls back to
    // another method, because each fallback would send the commands to a process which did not prove anything.
    private void authenticateToExternalTor(ExternalTorConfig externalTorConfig) {
        if (externalTorConfig.getControlPassword().isPresent()) {
            // As with netlayer: for an external Tor which has a HashedControlPassword instead of a cookie
            torController.authenticateWithPassword(externalTorConfig.getControlPassword().get());
            return;
        }
        if (!externalTorConfig.isCookieAuthentication()) {
            // No authentication required, but we still need to send an empty
            // AUTHENTICATE call to be able to send control commands
            torController.authenticate();
            return;
        }
        if (isWhonix) {
            // onion-grater, which filters the control port of the Whonix-Gateway, offers only authentication without a
            // secret and filters AUTHCHALLENGE, so SAFECOOKIE cannot work. The cookie file of a Whonix-Workstation
            // holds a fixed dummy value. netlayer and Bisq 2 before the library sent it, and onion-grater accepted it.
            log.warn("On Whonix, Bisq does not use the cookie of external_tor.config, because onion-grater on the " +
                    "Whonix-Gateway only accepts authentication without a secret");
            torController.authenticate();
            return;
        }
        Path authCookiePath = externalTorConfig.getCookieAuthFile()
                .orElseThrow(() -> new TorControlAuthenticationFailed("CookieAuthentication is 1, but CookieAuthFile " +
                        "is not set"));
        byte[] authCookie;
        // At most one byte more than a cookie: a large file, or a device such as /dev/zero, must not fill the memory
        // of Bisq or block its start.
        try (InputStream inputStream = Files.newInputStream(authCookiePath)) {
            authCookie = inputStream.readNBytes(AUTH_COOKIE_LENGTH + 1);
        } catch (IOException e) {
            throw new TorControlAuthenticationFailed("Could not read the cookie file " + authCookiePath + ": " + e);
        }
        if (authCookie.length != AUTH_COOKIE_LENGTH) {
            String length = authCookie.length > AUTH_COOKIE_LENGTH ?
                    "more than " + AUTH_COOKIE_LENGTH :
                    String.valueOf(authCookie.length);
            throw new TorControlAuthenticationFailed("The cookie file " + authCookiePath + " has " + length +
                    " bytes, but Tor writes " + AUTH_COOKIE_LENGTH + ". Check CookieAuthFile.");
        }
        torController.authenticateWithSafeCookie(authCookie);
    }

    /**
     * @return whether the data directory is new: it did not exist before, so no sandboxed Tor wrote it
     */
    private boolean prepareTorDirectories() {
        try {
            boolean isNewDataDirectory = !Files.isDirectory(torDirectories.getDataDirPath(), LinkOption.NOFOLLOW_LINKS);
            TorDirectoryMigration.migrateIfNeeded(torDirectories, TorBinaryZipExtractor::readTopLevelNames);
            boolean posixPermissionsAllowed = platformServices.supportsPosixPermissions();
            FileUtils.createDirectories(torDirectories.getDataDirPath(), posixPermissionsAllowed);
            FileUtils.createDirectories(torDirectories.getBinaryDirPath(), posixPermissionsAllowed);
            return isNewDataDirectory;
        } catch (IOException e) {
            log.warn("Couldn't prepare the Tor directories", e);
            throw new TorStartupFailedException("Couldn't prepare the directories of Tor in " +
                    torDirectories.getBaseDirPath() + ": " + e);
        }
    }

    /**
     * Records before Tor runs whether it runs in the sandbox, and clears the data directory before a Tor without the
     * sandbox runs on a directory which a sandboxed Tor may have written ({@link TorDataDirectoryMode}).
     */
    private void prepareDataDirectory(boolean isSandboxed, boolean isNewDataDirectory) {
        boolean posixPermissionsAllowed = platformServices.supportsPosixPermissions();
        try {
            if (isSandboxed) {
                TorDataDirectoryMode.recordSandboxed(torDirectories, posixPermissionsAllowed);
            } else if (TorDataDirectoryMode.prepareWithoutSandbox(torDirectories, isNewDataDirectory,
                    posixPermissionsAllowed)) {
                log.info("Bisq cleared the data directory of Tor, which a Tor in the sandbox may have written, " +
                        "because Tor runs without the sandbox now. Tor selects new entry guards.");
            }
        } catch (IOException e) {
            log.warn("Couldn't prepare the data directory of Tor", e);
            throw new TorStartupFailedException("Couldn't prepare the data directory of Tor " +
                    torDirectories.getDataDirPath() + ": " + e);
        }
    }

    /**
     * The Whonix-Gateway has the markers of Whonix, so Bisq would take it for a Workstation and connect to the
     * forwarded control port of the Gateway, which does not exist on the Gateway itself.
     */
    private void refuseWhonixGateway() {
        if (isWhonixGateway) {
            throw new TorStartupFailedException("Bisq does not run on a Whonix-Gateway, whose Tor serves the " +
                    "Whonix-Workstations behind it. Run Bisq on a Whonix-Workstation, which uses the Tor of the " +
                    "Gateway.");
        }
    }

    private boolean evaluateUseExternalTor(ExternalTorConfig externalTorConfig) {
        if (isWhonix) {
            log.info("Bisq runs on a Whonix system and use the Whonix system Tor");
            return true;
        } else {
            // If environment variable is set we take that.
            String torSkipLaunch = System.getenv(TOR_SKIP_LAUNCH);
            if (torSkipLaunch != null && !torSkipLaunch.trim().isEmpty()) {
                log.info("Environment variable 'TOR_SKIP_LAUNCH' is set to '{}'", torSkipLaunch);
                return torSkipLaunch.equals("1") ||
                        torSkipLaunch.equalsIgnoreCase("true") ||
                        torSkipLaunch.equalsIgnoreCase("yes");
            } else {
                // We check if external_tor.config value is set. If so we use that value.
                // Last we take the value form the JVM config.
                return externalTorConfig.getUseExternalTor().orElse(transportConfig.isUseExternalTor());
            }
        }
    }

    /**
     * Stops Tor, and ends a running initialization, which then fails. The future completes once the start of that
     * initialization has ended, so that no Tor of this service runs then. A call during a shutdown gets that shutdown.
     * The service can be started again.
     */
    public CompletableFuture<Boolean> shutdown() {
        log.info("shutdown");
        CompletableFuture<Boolean> shutdown = new CompletableFuture<>();
        Optional<CompletableFuture<Boolean>> endedInitialization;
        synchronized (lifecycleLock) {
            if (runningShutdown.isPresent()) {
                return runningShutdown.get();
            }
            endedInitialization = initialization;
            initialization = Optional.empty();
            runningShutdown = Optional.of(shutdown);
        }
        CompletableFuture.runAsync(() -> stopTor(endedInitialization), ForkJoinPool.commonPool())
                .whenComplete((nil, throwable) -> {
                    synchronized (lifecycleLock) {
                        runningShutdown = Optional.empty();
                    }
                    if (throwable == null) {
                        shutdown.complete(true);
                    } else {
                        shutdown.completeExceptionally(throwable);
                    }
                });
        return shutdown;
    }

    private void stopTor(Optional<CompletableFuture<Boolean>> endedInitialization) {
        // Ends a running start at its next step: its commands and its wait for the bootstrap fail, and its wait for the
        // control port ends with the process.
        RuntimeException failure = null;
        try {
            stopControllerAndProcess();
        } catch (RuntimeException e) {
            failure = e;
        }
        // Until the start has ended, the fields belong to it, and it may still create a controller or a process.
        endedInitialization.ifPresent(start -> start.handle((result, throwable) -> result).join());
        try {
            stopControllerAndProcess();
        } catch (RuntimeException e) {
            if (failure == null) failure = e;
            else failure.addSuppressed(e);
        }
        torController = null;
        torProcess = Optional.empty();
        onionServiceTargets.close();
        torSocksProxyFactory = Optional.empty();
        torVersion = Optional.empty();
        sandboxStatus = TorSandboxStatus.NOT_STARTED;
        if (failure != null) throw failure;
    }

    // Each step runs also when an earlier one fails, so that Tor is stopped in any case.
    private void stopControllerAndProcess() {
        torProcess.ifPresent(EmbeddedTorProcess::prepareForShutdown);
        TorController controller = torController;
        if (controller != null) {
            runQuietly(controller::shutdown, "Shutdown of the Tor controller failed");
        }
        torProcess.ifPresent(EmbeddedTorProcess::shutdown);
    }

    public CompletableFuture<String> publishOnionService(int localPort, int onionServicePort, OnionServiceKey onionServiceKey) {
        long ts = System.currentTimeMillis();
        String onionAddress = onionServiceKey.getOnionAddress();
        try {
            // The onion address only at debug level: a log which a user shares must not list the onion services of
            // the user together.
            log.debug("Publish onion service {}:{} (localPort={})", onionAddress, onionServicePort, localPort);
            int torTargetPort = onionServiceTargets.targetPortOf(onionAddress, localPort);
            // The controller publishes each onion address once per connection to Tor, also for concurrent calls.
            torController.publish(onionServiceKey, onionServicePort, torTargetPort);

            log.info("Tor onion service ready. Took {} ms (onionServicePort={}, localPort={})",
                    System.currentTimeMillis() - ts, onionServicePort, localPort);
            log.debug("Onion service {} is ready", onionAddress);

            return CompletableFuture.completedFuture(onionAddress);
        } catch (InterruptedException e) {
            log.warn("Can't create onion service. Thread got interrupted at publishOnionService method", e);
            Thread.currentThread().interrupt(); // Restore interrupted state
            return CompletableFuture.failedFuture(e);
        } catch (IOException e) {
            logPublicationFailure(onionAddress, e);
            return CompletableFuture.failedFuture(e);
        } catch (RuntimeException e) {
            Throwable cause = unwrapCompletionException(e);
            logPublicationFailure(onionAddress, cause);
            return CompletableFuture.failedFuture(cause);
        }
    }

    public CompletableFuture<ServerSocket> publishOnionServiceAndCreateServerSocket(int port, OnionServiceKey onionServiceKey) {
        long ts = System.currentTimeMillis();
        String onionAddress = onionServiceKey.getOnionAddress();
        OnionServiceTargets.Target target;
        try {
            target = onionServiceTargets.bindServerSocket(onionAddress);
        } catch (IOException e) {
            logPublicationFailure(onionAddress, e);
            return CompletableFuture.failedFuture(e);
        }

        try {
            log.debug("Publish onion service {}:{}", onionAddress, port);
            // The controller publishes each onion address once per connection to Tor, also for concurrent calls.
            torController.publish(onionServiceKey, port, target.torTargetPort());

            log.info("Tor onion service ready. Took {} ms (onionServicePort={})", System.currentTimeMillis() - ts, port);
            log.debug("Onion service {} is ready", onionAddress);

            return CompletableFuture.completedFuture(target.serverSocket());
        } catch (InterruptedException e) {
            log.warn("Can't create onion service. Thread got interrupted at publishOnionService method", e);
            closeQuietly(target.serverSocket());
            Thread.currentThread().interrupt(); // Restore interrupted state
            return CompletableFuture.failedFuture(e);
        } catch (RuntimeException e) {
            closeQuietly(target.serverSocket());
            Throwable cause = unwrapCompletionException(e);
            logPublicationFailure(onionAddress, cause);
            return CompletableFuture.failedFuture(cause);
        }
    }

    // The message of a failure can name onion addresses, which link the identities of a user in a log that the user
    // shares. Above debug level only a fixed text and the type of the failure.
    private static void logPublicationFailure(String onionAddress, Throwable cause) {
        log.error("Can't create onion service: {}", cause.getClass().getSimpleName());
        log.debug("Can't create onion service {}", onionAddress, cause);
    }

    // TorController.publish reports a failed publication as a CompletionException with the failure as its cause. The
    // hosts wait on the returned future, so the failure belongs into the future, as for the other failures.
    private static Throwable unwrapCompletionException(RuntimeException e) {
        return e instanceof CompletionException && e.getCause() != null ? e.getCause() : e;
    }

    /**
     * @return the address on which a server of the application has to listen, which it publishes with
     * {@link #publishOnionService}: the loopback address, except with the Tor of a Whonix-Gateway, which connects over
     * the internal network of Whonix. It belongs to the running Tor, so it is known once {@link #initialize()} has
     * returned.
     */
    public InetAddress getOnionServiceBindAddress() {
        return onionServiceTargets.getBindAddress();
    }

    public CompletableFuture<Boolean> isOnionServiceOnlineAsync(String onionUrl) {
        return torController.isOnionServiceOnlineAsync(onionUrl)
                .orTimeout(1, TimeUnit.MINUTES);
    }

    public Socket getSocket(String host, int port, String streamId, int socketTimeout) throws IOException {
        TorSocksProxyFactory socksProxyFactory = torSocksProxyFactory.orElseThrow();
        return socksProxyFactory.getSocket(host, port, streamId, socketTimeout);
    }

    public Socks5Proxy getSocks5Proxy() throws IOException {
        TorSocksProxyFactory socksProxyFactory = torSocksProxyFactory.orElseThrow();
        return socksProxyFactory.getSocks5Proxy();
    }

    private void connectToExternalTor(ExternalTorConfig externalTorConfig) {
        String controlHost = externalTorConfig.getControlHost();
        int controlPort = externalTorConfig.getControlPort();
        if (torController != null) {
            torController.shutdown();
        }
        torController = torControllerFactory.get();
        torController.initialize(controlHost, controlPort);

        authenticateToExternalTor(externalTorConfig);
        // A system Tor may still bootstrap, for example right after the start of the system.
        torController.awaitBootstrapOfExternalTor();

        onionServiceTargets.close();
        onionServiceTargets = new DirectOnionServiceTargets(getExternalTorBindAddress());

        torVersion = torController.getTorVersion();
        log.info("The external Tor at {}:{} has version {}", controlHost, controlPort,
                torVersion.orElse("unknown"));

        List<TorController.SocksListener> socksListeners = torController.getSocksListeners();
        InetSocketAddress socksAddress = selectSocksAddress(controlHost, isLoopbackAddress(controlHost), socksListeners);
        log.info("The external Tor listens for SOCKS connections on {}. Bisq connects to {}:{}",
                describe(socksListeners), socksAddress.getHostString(), socksAddress.getPort());
        refuseSocksPortWithoutStreamIsolation(socksAddress.getPort());
        torSocksProxyFactory = Optional.of(new TorSocksProxyFactory(socksAddress.getHostString(), socksAddress.getPort()));
    }

    /**
     * The address of the SOCKS port of an external Tor: the first TCP listener which Bisq can reach. A listener on a
     * specific address is reached there. A listener on a wildcard address accepts connections on every address of the
     * host of Tor, so Bisq connects to the control host. A loopback address is an address of the host of Tor, which is
     * this host only if the control host is a loopback address as well.
     *
     * @param isControlHostLoopback whether the control host is a loopback address, so that Tor runs on this host
     * @throws TorStartupFailedException if Bisq can reach none of the listeners
     */
    @VisibleForTesting
    static InetSocketAddress selectSocksAddress(String controlHost,
                                                boolean isControlHostLoopback,
                                                List<TorController.SocksListener> socksListeners) {
        for (TorController.SocksListener listener : socksListeners) {
            Optional<InetAddress> address = InetAddresses.isInetAddress(listener.address()) ?
                    Optional.of(InetAddresses.forString(listener.address())) :
                    Optional.empty();
            if (address.filter(InetAddress::isAnyLocalAddress).isPresent()) {
                return InetSocketAddress.createUnresolved(controlHost, listener.port());
            }
            if (address.filter(InetAddress::isLoopbackAddress).isEmpty() || isControlHostLoopback) {
                return InetSocketAddress.createUnresolved(listener.address(), listener.port());
            }
        }
        if (socksListeners.isEmpty()) {
            throw new TorStartupFailedException("Tor has no TCP SOCKS listener");
        }
        throw new TorStartupFailedException("Tor listens for SOCKS connections only on the loopback address of its " +
                "host " + controlHost + " (" + describe(socksListeners) + "), which Bisq cannot reach from this host. " +
                "Add a SocksPort on an address of that host which this host can reach to the configuration of the " +
                "external Tor");
    }

    // IPv6 addresses in brackets, as Tor reports them
    private static String describe(List<TorController.SocksListener> socksListeners) {
        return socksListeners.stream()
                .map(listener -> listener.address().contains(":") ?
                        "[" + listener.address() + "]:" + listener.port() :
                        listener.address() + ":" + listener.port())
                .collect(Collectors.joining(", "));
    }

    // A host name which does not resolve is no loopback address. The control connection resolved it already.
    private static boolean isLoopbackAddress(String host) {
        try {
            return InetAddress.getByName(host).isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * {@link #getSocket} sends SOCKS credentials derived from the stream ID, so that Tor puts the streams of different
     * stream IDs on different circuits, which both applications require for their connections. The Tor which Bisq
     * starts always does so; the configuration of an external Tor can turn it off for its SOCKS port.
     */
    private void refuseSocksPortWithoutStreamIsolation(int socksPort) {
        Optional<List<String>> entriesWithoutIsolation = torController.findSocksPortsWithoutSocksAuthIsolation(socksPort);
        if (entriesWithoutIsolation.isEmpty()) {
            log.info("The control port of the external Tor does not report its SocksPort configuration, so Bisq " +
                    "cannot check that the SOCKS port {} isolates streams by their SOCKS credentials", socksPort);
            return;
        }
        if (!entriesWithoutIsolation.get().isEmpty()) {
            throw new TorStartupFailedException("Its SOCKS port " + socksPort + " does not isolate streams by their " +
                    "SOCKS credentials (SocksPort " + String.join(", ", entriesWithoutIsolation.get()) + "), so Tor " +
                    "could put the connections of different identities of Bisq on one circuit. Remove " +
                    "NoIsolateSOCKSAuth from that SocksPort in the configuration of the external Tor");
        }
    }

    private String getExternalTorUnavailableMessage(ExternalTorConfig externalTorConfig, RuntimeException cause) {
        String location = externalTorConfig.getControlHost() + ":" + externalTorConfig.getControlPort();
        String hint;
        if (!isWhonix) {
            hint = "Start the external Tor or correct " + torDirectories.getExternalTorConfigPath() + ". Bisq uses an " +
                    "external Tor if UseExternalTor is 1 there, if the environment variable " + TOR_SKIP_LAUNCH +
                    " is 1, or if the application is configured to use one.";
        } else if (cause instanceof TorCommandFilteredException) {
            // Its message gives the advice for onion-grater already.
            hint = "Check also " + torDirectories.getExternalTorConfigPath() + ".";
        } else {
            hint = "Check that the Tor of the Whonix-Gateway runs, that the system of the Whonix-Gateway is updated " +
                    "and that the onion-grater profile of Bisq is enabled there with \"sudo onion-grater-add 40_bisq\". " +
                    "Check also " + torDirectories.getExternalTorConfigPath() + ".";
        }
        return "Bisq is configured to use a Tor which runs outside Bisq, but it cannot use the Tor at " + location +
                ": " + withoutFinalPeriod(cause.getMessage()) + ". Bisq does not start its own Tor instead, because it " +
                "would connect to the Tor network without the settings of the external Tor, for example its bridges. " +
                hint;
    }

    // The message of the cause goes into a sentence of another message, which ends it.
    private static String withoutFinalPeriod(String message) {
        String text = String.valueOf(message);
        return text.endsWith(".") ? text.substring(0, text.length() - 1) : text;
    }

    private ExternalTorConfig readExternalTorConfig() {
        Path torConfigFilePath = torDirectories.getExternalTorConfigPath();
        String torConfig;
        try {
            if (!Files.exists(torConfigFilePath)) {
                torConfig = FileUtils.readStringFromResource("tor/" + TorDirectories.EXTERNAL_TOR_CONFIG_FILE_NAME);
                FileUtils.writeToPath(torConfig, torConfigFilePath, platformServices.supportsPosixPermissions());
            } else {
                torConfig = FileUtils.readUTF8String(torConfigFilePath);
            }
        } catch (IOException e) {
            // Without the file, Bisq cannot know whether the user wants to use an external Tor.
            log.warn("Could not read {}", torConfigFilePath, e);
            throw new IllegalStateException("Could not read " + torConfigFilePath + ": " + e);
        }
        try {
            return ExternalTorConfig.parse(torConfig);
        } catch (IllegalArgumentException e) {
            // Without the cause, so that the message which names the file is the root cause which Bisq 2 shows
            throw new IllegalArgumentException("Invalid " + torConfigFilePath + ": " + e.getMessage());
        }
    }

    private void makeTorDir() {
        try {
            FileUtils.createDirectories(torDirectories.getBaseDirPath(), platformServices.supportsPosixPermissions());
        } catch (IOException e) {
            log.warn("Couldn't create the Tor directory", e);
            throw new TorStartupFailedException("Couldn't create the Tor directory " +
                    torDirectories.getBaseDirPath() + ": " + e);
        }
    }

    /**
     * @param sandboxedRun present if sandy starts Tor. sandy can refuse the start after a passed check, for example
     *                     when another process took a port of the policy in between. It exits with its own status and
     *                     prints the reason on standard error, which is in the stderr log. Tor can exit with that
     *                     status too, so only a status record which shows that sandy ended the run before Tor ran
     *                     gets the advice to turn the sandbox off.
     */
    @VisibleForTesting
    static void waitUntilControlPortAnswers(int controlPort,
                                            EmbeddedTorProcess embeddedTorProcess,
                                            Optional<SandboxedRun> sandboxedRun)
            throws InterruptedException, IOException {
        try {
            long start = System.currentTimeMillis();
            while (!ControlPortProbe.isTorAnswering(controlPort)) {
                if (!embeddedTorProcess.isAlive()) {
                    throw sandboxedRun.isPresent() ?
                            endOfSandboxedRun(embeddedTorProcess, sandboxedRun.get()) :
                            new IOException("Embedded Tor exited before it answered on its control port. " +
                                    embeddedTorProcess.getStartupDiagnostics());
                }
                if (System.currentTimeMillis() - start > CONTROL_PORT_TIMEOUT_MS) {
                    throw new IOException("Tor did not answer on its control port " + controlPort + " within " +
                            CONTROL_PORT_TIMEOUT_MS + " ms. " +
                            startupDiagnostics(embeddedTorProcess, sandboxedRun.isPresent()));
                }
                Thread.sleep(CONTROL_PORT_POLL_INTERVAL_MS);
            }
        } finally {
            // The record is read, or Tor answered and the record is of no further use.
            sandboxedRun.ifPresent(run -> removeStatusRecordQuietly(run.statusRecordPath()));
        }
    }

    /**
     * @return the failure of a start whose Tor may have run
     * @throws SandboxUnavailableException if the status record shows that sandy ended the run before Tor ran
     */
    private static IOException endOfSandboxedRun(EmbeddedTorProcess embeddedTorProcess, SandboxedRun sandboxedRun) {
        Optional<SandyStatusRecord> statusRecord;
        try {
            statusRecord = SandyStatusRecord.read(sandboxedRun.statusRecordPath());
        } catch (IOException e) {
            return new IOException("Embedded Tor exited before it answered on its control port, and Bisq could not " +
                    "read the status record of sandy, which tells whether Tor ran: " + e.getMessage() + ". " +
                    embeddedTorProcess.getStartupDiagnostics(SANDBOXED_STDERR_LABEL));
        }
        int exitCode = embeddedTorProcess.getExitCode().orElseThrow();
        // The facts which Bisq knows come before the quote of the standard error, which Tor can have written.
        String record = "statusRecord=[" + statusRecord.map(SandyStatusRecord::toString).orElse("none") + "], ";
        if (Sandy.endedBeforeTheProgramRan(sandboxedRun.staysParent(), exitCode, statusRecord)) {
            // Without a cause, so that the reason and the hint are the root cause which Bisq 2 shows
            throw new SandyRefusalException("sandy did not start Tor. " + record +
                    embeddedTorProcess.getStartupDiagnostics(SANDBOXED_STDERR_LABEL), sandboxedRun.optOutHint());
        }
        return new IOException("Embedded Tor exited before it answered on its control port." +
                windowsSessionHint(Optional.of(exitCode)) + " " + record +
                embeddedTorProcess.getStartupDiagnostics(SANDBOXED_STDERR_LABEL));
    }

    private static String startupDiagnostics(EmbeddedTorProcess embeddedTorProcess, boolean isSandboxed) {
        return isSandboxed ?
                embeddedTorProcess.getStartupDiagnostics(SANDBOXED_STDERR_LABEL) :
                embeddedTorProcess.getStartupDiagnostics();
    }

    private static void removeStatusRecordQuietly(Path statusRecordPath) {
        try {
            Files.deleteIfExists(statusRecordPath);
        } catch (IOException e) {
            log.warn("Couldn't remove the status record of sandy {}", statusRecordPath, e);
        }
    }

    /**
     * tor.exe ends with STATUS_DLL_INIT_FAILED before it runs when user32.dll cannot initialize in an AppContainer: in
     * a session whose window station does not admit AppContainers, such as session 0 or a session over SSH. sandy
     * check only warns in session 0, without refusing, and does not detect other such window stations (sandy
     * docs/windows.md, limitation 13), and sandy passes the status on.
     */
    @VisibleForTesting
    static String windowsSessionHint(Optional<Integer> exitCode) {
        boolean isDllInitFailed = exitCode.filter(code -> code == STATUS_DLL_INIT_FAILED).isPresent();
        return isDllInitFailed ? " Tor ended with STATUS_DLL_INIT_FAILED, likely because it started in a session " +
                "whose window station does not admit the AppContainer of its sandbox: as a Windows service, in " +
                "session 0 or in a session over SSH. Start Bisq in a desktop session." : "";
    }

    private void installTorIfNotUpToDate() {
        var torInstaller = new TorInstaller(torDirectories.getBinaryDirPath());
        torInstaller.installIfNotUpToDate();
    }

    private static boolean isSet(Map<String, String> torrcConfigMap, String key) {
        return torrcConfigMap.keySet().stream().anyMatch(existingKey -> TorrcClientConfigFactory.sets(existingKey, key));
    }

    /**
     * The bundled Tor looks for its GeoIP files in a directory of its build below /var/tmp/dist, where any local user
     * can create files, unless the torrc names them. Bisq names the files of the bundle also when one is missing from a
     * damaged installation: Tor then runs without country data instead of reading that directory. A torrc override of
     * the user still applies.
     */
    @VisibleForTesting
    static void putBundledGeoIpFiles(Map<String, String> torrcConfigMap, TorDirectories torDirectories) {
        putIfNotSet(torrcConfigMap, GEOIP_FILE, torDirectories.getBundledGeoIpFilePath());
        putIfNotSet(torrcConfigMap, GEOIP_V6_FILE, torDirectories.getBundledGeoIpv6FilePath());
    }

    private static void putIfNotSet(Map<String, String> torrcConfigMap, String key, Path filePath) {
        if (isSet(torrcConfigMap, key)) {
            return;
        }
        if (!Files.exists(filePath)) {
            log.warn("The Tor bundle has no {}. Tor runs without its country data.", filePath.getFileName());
        }
        torrcConfigMap.put(key, TorrcSyntax.toValue(filePath.toAbsolutePath().toString()));
    }

    private void createEmptyOpenSslConfig() {
        Path openSslConfigPath = torDirectories.getOpenSslConfigPath();
        try {
            FileUtils.writeToPath("", openSslConfigPath, platformServices.supportsPosixPermissions());
        } catch (IOException e) {
            log.warn("Couldn't write {}", openSslConfigPath.getFileName(), e);
            throw new TorStartupFailedException("Couldn't write " + openSslConfigPath.getFileName(), e);
        }
    }

    /**
     * @param isSandboxed     Tor runs in the sandbox, which on Linux gives it no {@code /proc/meminfo}
     * @param socks5ProxyPort the port of the egress broker of sandy, through which Tor connects out in the level of
     *                        its sandbox
     */
    private Map<String, String> createTorrcConfigFile(PasswordDigest hashedControlPassword,
                                                      TorListenerPorts listenerPorts,
                                                      List<Map.Entry<String, String>> bridgeEntries,
                                                      boolean isSandboxed,
                                                      OptionalInt socks5ProxyPort) {
        BridgeConfig bridgeConfig = transportConfig.getBridgeConfig();
        TorrcClientConfigFactory torrcClientConfigFactory = TorrcClientConfigFactory.builder()
                .isTestNetwork(transportConfig.isTestNetwork())
                .dataDirPath(torDirectories.getDataDirPath())
                .hashedControlPassword(hashedControlPassword)
                .usesBridges(bridgeConfig.isUsed())
                .controlPort(listenerPorts.control().innerPort())
                .socksPort(listenerPorts.socks().innerPort())
                .build();

        Map<String, String> torrcOverrideConfigs = transportConfig.getTorrcOverrides();
        Map<String, String> torrcConfigMap = torrcClientConfigFactory.torrcClientConfigMap(torrcOverrideConfigs);
        putBundledGeoIpFiles(torrcConfigMap, torDirectories);
        // The policy of the sandbox refuses torrc overrides of the proxy options, so this one is Bisq's.
        socks5ProxyPort.ifPresent(port -> torrcConfigMap.put(SOCKS5_PROXY, LoopbackPorts.IPV4_LOOPBACK.getHostAddress() +
                ":" + port));
        if (isSandboxed && !isSet(torrcConfigMap, MAX_MEM_IN_QUEUES)) {
            // Tor derives its default from the size of the memory, which on Linux it reads from /proc/meminfo. The
            // sandbox does not grant it: a grant of a /proc path would cost the PID namespace that isolates the signals
            // of Tor below Linux 6.12.
            torrcConfigMap.put(MAX_MEM_IN_QUEUES, TorMemoryLimit.torrcValue());
        }

        var torrcFileGenerator = new TorrcFileGenerator(torDirectories.getTorrcPath(),
                torrcConfigMap,
                bridgeEntries,
                transportConfig.getDirectoryAuthorities());
        torrcFileGenerator.generate();
        return torrcConfigMap;
    }

    private List<Map.Entry<String, String>> createBridgeTorrcEntries(BridgeConfig bridgeConfig) {
        PluggableTransportConfig pluggableTransportConfig =
                PluggableTransportConfig.read(torDirectories.getPluggableTransportConfigPath());
        Path bundleDirPath = torDirectories.getBinaryDirPath();
        List<Map.Entry<String, String>> bridgeEntries = BridgeTorrcEntries.create(bridgeConfig,
                pluggableTransportConfig,
                programName -> PluggableTransportPrograms.find(bundleDirPath, programName));
        // The bridge lines are not logged: a bridge which the user got privately would be blocked once it is known.
        log.info("The embedded Tor connects through {}",
                bridgeConfig.getBuiltInBridges()
                        .map(name -> "the built-in bridges of the type " + name)
                        .orElse(bridgeConfig.getCustomBridgeLines().size() + " bridges of the user"));
        return bridgeEntries;
    }

    private InetAddress getExternalTorBindAddress() {
        if (!isWhonix) {
            return LoopbackPorts.IPV4_LOOPBACK;
        }
        try {
            // The Tor of Whonix runs on the Whonix-Gateway and connects to the workstation over the internal network.
            return InetAddress.getByName("0.0.0.0");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }


    private static void closeQuietly(ServerSocket serverSocket) {
        try {
            serverSocket.close();
        } catch (IOException ignore) {
        }
    }
}
