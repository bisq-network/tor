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

import bisq.network.tor.common.file.FileUtils;
import bisq.network.tor.common.platform.OS;
import bisq.network.tor.common.platform.Platform;
import bisq.network.tor.common.torrc.TorrcFileGenerator;
import bisq.network.tor.controller.PasswordDigest;
import bisq.network.tor.installer.TorInstaller;
import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.LoopbackPorts;
import bisq.network.tor.process.TorDirectories;
import bisq.network.tor.process.TorListenerPorts;
import bisq.network.tor.process.TorListenerPorts.PortMapping;
import bisq.network.tor.sandbox.SandboxedTransports;
import bisq.network.tor.sandbox.Sandy;
import bisq.network.tor.sandbox.SandyBinary;
import bisq.network.tor.sandbox.SandyPolicy;
import bisq.network.tor.sandbox.TorMemoryLimit;
import bisq.network.tor.sandbox.TorSandboxPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs the bundled tor through sandy in the levels of the Linux policy which TorSandboxPolicy renders, with the command
 * line and the environment of TorService, and checks what the sandbox enforces. sandy runs a named level on any host
 * that can enforce it, so a strong host runs the fallback levels too. The probes of the enforcement run busybox in the
 * base level of linux.toml, which Tor without pluggable transports gets, and of linux-transports.toml, which Tor with
 * obfs4 bridges gets; both as TorSandboxPolicy renders them for the bundled tor. The status record of sandy tells a
 * refusal of sandy from a program which exits with the status of sandy.
 */
@Timeout(120)
class SandboxEnforcementTest {
    // The owner check of Tor runs every 15 seconds.
    private static final long AFTER_FIRST_OWNER_CHECK_MS = 20_000;
    // sandy sends SIGTERM when the parent ends, and SIGKILL 5 seconds later.
    private static final long END_WITH_PARENT_TIMEOUT_MS = 10_000;
    // The program of the probes. A shell in the sandbox finds its applets only through the path of busybox.
    private static final Path BUSYBOX = Paths.get("/usr/bin/busybox");
    // The program of the transport in linux-transports.toml: the only program besides busybox which a probe may start
    private static final Path TRANSPORT_PROGRAM = Paths.get("/usr/bin/true");
    private static final String OPT_OUT_HINT = "Turn the sandbox off to test.";

    @TempDir
    Path torDir;
    @TempDir
    Path outsideDir;
    private TorDirectories directories;
    private Path torBinaryPath;
    private Path sandyPath;
    private final List<Process> parents = new ArrayList<>();
    private final List<EmbeddedTorProcess> torProcesses = new ArrayList<>();
    private int egressPort;

    @BeforeEach
    void setUp() throws IOException {
        assumeTrue(OS.isLinux(), "The test checks the sandbox of Linux");
        assumeTrue(getClass().getClassLoader().getResource("tor.zip") != null, "The build packaged no Tor bundle");
        assumeTrue(getClass().getClassLoader().getResource("sandy/SHA256SUMS") != null,
                "The build packaged no sandy binary");
        directories = new TorDirectories(torDir);
        FileUtils.createDirectories(directories.getDataDirPath());
        // As TorService prepares a start
        new TorInstaller(directories.getBinaryDirPath()).installIfNotUpToDate();
        Files.writeString(directories.getOpenSslConfigPath(), "");
        torBinaryPath = directories.getBundledTorBinaryPath();
        sandyPath = SandyBinary.install(directories.getSandyDirPath(), Platform.getPlatform());
    }

    @AfterEach
    void tearDown() {
        torProcesses.forEach(EmbeddedTorProcess::shutdown);
        parents.forEach(Process::destroyForcibly);
    }

    /**
     * In the PID namespace of contained, Tor cannot see its parent. Without an owner process it outlives its first
     * owner check, which would otherwise end it before Bisq's bootstrap reset the option.
     */
    @Test
    void torWithoutAnOwnerProcessOutlivesItsFirstOwnerCheckInThePidNamespace() throws Exception {
        EmbeddedTorProcess tor = startTorInLevel("contained", startParent());

        Thread.sleep(AFTER_FIRST_OWNER_CHECK_MS);

        assertThat(tor.isAlive()).as("Tor in the level contained after its first owner check: %s",
                tor.getStartupDiagnostics()).isTrue();
    }

    // Tor gets no owner process in a level that ends with its parent, because sandy ends it with the parent.
    @ParameterizedTest
    @ValueSource(strings = {"base", "contained", "host-network"})
    void torEndsWithTheParentInALevelThatEndsWithIt(String levelName) throws Exception {
        Process parent = startParent();
        EmbeddedTorProcess tor = startTorInLevel(levelName, parent);
        assertThat(tor.isAlive()).isTrue();

        parent.destroyForcibly();

        long deadline = System.currentTimeMillis() + END_WITH_PARENT_TIMEOUT_MS;
        while (tor.isAlive() && System.currentTimeMillis() < deadline) {
            Thread.sleep(100);
        }
        assertThat(tor.isAlive()).as("Tor in the level %s after its parent ended", levelName).isFalse();
    }

    @Test
    void theProgramSeesNoPathOutsideItsPolicy() throws Exception {
        SandyPolicy policy = linuxPolicy();
        Path outsideFile = Files.writeString(outsideDir.resolve("outside.txt"), "content outside the policy");

        ProbeResult read = probe(policy, "cat", outsideFile.toString());
        ProbeResult listParent = probe(policy, "ls", torDir.getParent().toString());
        ProbeResult listProc = probe(policy, "ls", "/proc");

        assertThat(read.exitCode()).isNotZero();
        assertThat(read.output()).contains("No such file or directory").doesNotContain("content outside the policy");
        // The directories above a granted path exist in the view, without their content.
        assertThat(listParent.exitCode()).isNotZero();
        assertThat(listParent.output()).contains("Permission denied").doesNotContain(outsideDir.getFileName().toString());
        assertThat(listProc.exitCode()).isNotZero();
        assertThat(listProc.output()).contains("No such file or directory");
    }

    @Test
    void theProgramReadsItsTorrcAndTheGeoIpFileAndWritesOnlyItsDataDirectory() throws Exception {
        SandyPolicy policy = linuxPolicy();
        Path torrc = directories.getTorrcPath();
        Path dataFile = directories.getDataDirPath().resolve("probe");

        ProbeResult readTorrc = probe(policy, "cat", torrc.toString());
        ProbeResult writeTorrc = probe(policy, "sh", "-c", "echo changed > " + torrc);
        ProbeResult writeData = probe(policy, "sh", "-c", "echo written > " + dataFile);

        assertThat(readTorrc.exitCode()).isZero();
        assertThat(readTorrc.output()).contains("SocksPort 0");
        assertThat(writeTorrc.exitCode()).isNotZero();
        assertThat(writeTorrc.output()).contains("Read-only file system");
        assertThat(Files.readString(torrc)).doesNotContain("changed");
        assertThat(writeData.exitCode()).isZero();
        assertThat(Files.readString(dataFile)).isEqualTo("written\n");
        // Tor reads its bundle, but cannot change what Bisq executes or reads at the next start.
        Path geoIp = directories.getBundledGeoIpFilePath();
        ProbeResult readBundle = probe(policy, "head", "-c", "1", geoIp.toString());
        ProbeResult writeBundle = probe(policy, "sh", "-c", "echo changed > " + geoIp);
        assertThat(readBundle.exitCode()).isZero();
        assertThat(writeBundle.exitCode()).isNotZero();
        assertThat(writeBundle.output()).contains("Read-only file system");
    }

    @Test
    void theProgramCanStartNoProcessAndSignalNoProcessOutside() throws Exception {
        SandyPolicy policy = linuxPolicy();

        ProbeResult fork = probe(policy, "sh", "-c", TRANSPORT_PROGRAM + "; echo after");
        ProbeResult signal = probe(policy, "kill", "-0", Long.toString(ProcessHandle.current().pid()));

        assertThat(fork.output()).contains("can't fork: Operation not permitted").doesNotContain("after");
        assertThat(signal.exitCode()).isNotZero();
        assertThat(signal.output()).contains("Operation not permitted");
    }

    @Test
    void theProgramReachesNoLoopbackListenerOfTheHost() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK)) {
            for (SandyPolicy policy : List.of(linuxPolicy(), transportsPolicy())) {
                ProbeResult connect = probe(policy, "nc", "-w", "5", "127.0.0.1",
                        Integer.toString(listener.getLocalPort()));

                assertThat(connect.exitCode()).isNotZero();
                assertThat(connect.output()).contains("Connection refused");
            }
            assertThat(acceptedLine(listener)).isEmpty();
        }
    }

    @Test
    void forwardedPortsReachTheOnionServicesOfBisq() throws Exception {
        try (ServerSocket onionService = new ServerSocket(0, 1, LoopbackPorts.IPV4_LOOPBACK)) {
            int innerPort = LoopbackPorts.allocate(1).get(0);
            SandyPolicy policy = transportsPolicy(
                    List.of(new SandyPolicy.ForwardedPort(innerPort, onionService.getLocalPort())));

            // nc ends when the onion service closes the connection.
            CompletableFuture<String> received = CompletableFuture.supplyAsync(() -> acceptedLine(onionService));

            ProbeResult connect = probe(policy, "sh", "-c", "echo forwarded | " + BUSYBOX + " nc -w 5 127.0.0.1 " +
                    innerPort);

            assertThat(connect.exitCode()).as(connect.output()).isZero();
            assertThat(received.get(10, TimeUnit.SECONDS)).isEqualTo("forwarded");
        }
    }

    // A SOCKS5 greeting without authentication, then a CONNECT to 127.0.0.1:22
    @Test
    void theEgressBrokerRefusesAddressesOfTheHost() throws Exception {
        SandyPolicy policy = transportsPolicy();
        String request = "\\005\\001\\000\\005\\001\\000\\001\\177\\000\\000\\001\\000\\026";

        ProbeResult socks = probe(policy, "sh", "-c", "printf '" + request + "' | " + BUSYBOX + " nc -w 5 127.0.0.1 " +
                egressPort + " | " + BUSYBOX + " od -An -tx1");

        // Method 00 accepted, then reply 02: not allowed by the rule set of the broker
        assertThat(socks.output().replaceAll("\\s+", " ")).contains("05 00 05 02");
    }

    @Test
    void transportsStartOnlyTheProgramsOfTheirPolicy() throws Exception {
        SandyPolicy policy = transportsPolicy();

        ProbeResult granted = probe(policy, "sh", "-c", TRANSPORT_PROGRAM + " && echo granted program ran");
        ProbeResult other = probe(policy, "sh", "-c", "/usr/bin/id; echo rc=$?");

        assertThat(granted.output()).contains("granted program ran");
        assertThat(other.output()).contains("not found").contains("rc=127");
    }

    // With transports the program runs in a PID namespace, where no process outside exists.
    @Test
    void transportsSeeNoProcessOutside() throws Exception {
        SandyPolicy policy = transportsPolicy();

        ProbeResult signal = probe(policy, "sh", "-c", "kill -0 " + ProcessHandle.current().pid() + "; echo rc=$?");

        assertThat(signal.output()).contains("No such process").contains("rc=1");
    }

    // Another process holds the port on which sandy relays the SOCKS port of Tor, so sandy refuses before Tor runs.
    @Test
    void aPortWhichAnotherProcessHoldsIsARefusalOfSandyWithTheAdvice() throws Exception {
        TorListenerPorts listenerPorts = allocateListenerPorts();
        SandyPolicy policy = torPolicy(listenerPorts);
        Sandy.Level level = selectedLevel(policy);

        try (ServerSocket ignored = new ServerSocket(listenerPorts.socks().outerPort(), 1,
                LoopbackPorts.IPV4_LOOPBACK)) {
            EmbeddedTorProcess tor = startInLevel(policy, level, EmbeddedTorProcess.torCommand(torBinaryPath,
                    directories.getTorrcPath()));

            // A refusal which can pass, which the start of TorService tries once more with other ports
            assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(listenerPorts.control().outerPort(), tor,
                    sandboxedRun(level)))
                    .isInstanceOf(TorService.SandyRefusalException.class)
                    .hasMessageContaining("statusRecord=[level " + level.name() + ", failed]")
                    .hasMessageContaining("Address in use")
                    .hasMessageContaining(OPT_OUT_HINT);
        }
        assertThat(directories.getSandyStatusRecordPath()).doesNotExist();
    }

    // sandy check tries the ports of the policy and cannot tell now while another process holds one.
    @Test
    void aPortWhichAnotherProcessHoldsAtTheCheckIsARefusalWhichCanPass() throws Exception {
        TorListenerPorts listenerPorts = allocateListenerPorts();
        SandyPolicy policy = torPolicy(listenerPorts);
        Sandy sandy = new Sandy(sandyPath, Long.toString(ProcessHandle.current().pid()));

        Sandy.CheckResult checkResult;
        try (ServerSocket ignored = new ServerSocket(listenerPorts.control().outerPort(), 1,
                LoopbackPorts.IPV4_LOOPBACK)) {
            checkResult = sandy.check(policy, torBinaryPath);
        }

        assertThat(checkResult.exitCode()).as(checkResult.report()).isEqualTo(Sandy.EXIT_STATUS_NOT_STARTED);
        assertThat(TorService.refusalOfCheck(checkResult, OPT_OUT_HINT))
                .isInstanceOf(TorService.SandyRefusalException.class)
                .hasMessageContaining(Integer.toString(listenerPorts.control().outerPort()));
    }

    /**
     * A compromised Tor chooses its exit status and what it writes to its standard error, but not the status record
     * of sandy, in which sandy names the process ID of the program once it runs it. In linux.toml sandy replaces itself
     * with the program, in linux-transports.toml it stays its parent and contains the processes of the program.
     */
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void aProgramWhichExitsWithTheStatusOfSandyGetsNoAdviceToTurnTheSandboxOff(boolean withTransports)
            throws Exception {
        SandyPolicy policy = withTransports ? transportsPolicy() : linuxPolicy();
        Sandy.Level level = selectedLevel(policy);
        assertThat(Sandy.staysParent(OS.LINUX, level)).as("sandy stays the parent in level %s", level)
                .isEqualTo(withTransports);
        int closedPort = LoopbackPorts.allocate(1).get(0);

        EmbeddedTorProcess program = startInLevel(policy, level, List.of(BUSYBOX.toString(), "sh", "-c",
                "echo 'sandy: this system cannot run the sandbox' >&2; exit 125"));

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, program, sandboxedRun(level)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exited before it answered")
                .hasMessageContaining("exitCode=125")
                .hasMessageContaining("statusRecord=[level " + level.name() + ", pid ")
                .hasMessageNotContaining(OPT_OUT_HINT);
    }

    // The level which sandy check selects for the policy, with the requirements which it enforces there
    private Sandy.Level selectedLevel(SandyPolicy policy) {
        Sandy.CheckResult checkResult = new Sandy(sandyPath, Long.toString(ProcessHandle.current().pid()))
                .check(policy, torBinaryPath);
        assumeTrue(checkResult.isEnforceable(), "This host enforces no level of the policy:\n" + checkResult.report());
        return checkResult.selectedLevel().orElseThrow();
    }

    // Starts the program as TorService starts Tor in the level, with this test as the parent which Tor ends with
    private EmbeddedTorProcess startInLevel(SandyPolicy policy, Sandy.Level level, List<String> program)
            throws IOException {
        Sandy sandy = new Sandy(sandyPath, Long.toString(ProcessHandle.current().pid()));
        Files.deleteIfExists(directories.getSandyStatusRecordPath());
        var process = new EmbeddedTorProcess(sandy.runCommand(policy, level, directories.getSandyStatusRecordPath(),
                program),
                policy.workingDirPath(),
                Sandy::removeLoaderVariables,
                directories.getLogPath(),
                Optional.of(Sandy.policyInput(policy)));
        torProcesses.add(process);
        process.start();
        return process;
    }

    private Optional<TorService.SandboxedRun> sandboxedRun(Sandy.Level level) {
        return Optional.of(new TorService.SandboxedRun(directories.getSandyStatusRecordPath(),
                Sandy.staysParent(OS.LINUX, level), OPT_OUT_HINT));
    }

    // A process which sandy takes as the parent of Tor, so that the test can end it
    private Process startParent() throws IOException {
        Process parent = new ProcessBuilder("sleep", "600").start();
        parents.add(parent);
        return parent;
    }

    // Starts Tor as TorService starts it in the level, with the parent instead of Bisq, and waits until it answers.
    private EmbeddedTorProcess startTorInLevel(String levelName, Process parent) throws Exception {
        TorListenerPorts listenerPorts = allocateListenerPorts();
        SandyPolicy policy = torPolicy(listenerPorts);

        assumeEnforceable(policy, levelName);
        String parentPid = Long.toString(parent.pid());
        Sandy sandy = new Sandy(sandyPath, parentPid);
        var level = new Sandy.Level(levelName, Set.of(Sandy.ENDS_WITH_PARENT));
        List<String> torCommand = TorService.sandboxedTorCommand(torBinaryPath, directories.getTorrcPath(), level,
                parentPid);
        Files.deleteIfExists(directories.getSandyStatusRecordPath());
        var tor = new EmbeddedTorProcess(sandy.runCommand(policy, level, directories.getSandyStatusRecordPath(),
                torCommand),
                policy.workingDirPath(),
                Sandy::removeLoaderVariables,
                directories.getLogPath(),
                Optional.of(Sandy.policyInput(policy)));
        torProcesses.add(tor);
        tor.start();
        TorService.waitUntilControlPortAnswers(listenerPorts.control().outerPort(), tor, Optional.empty());
        return tor;
    }

    private static TorListenerPorts allocateListenerPorts() throws IOException {
        List<Integer> ports = LoopbackPorts.allocate(5);
        return new TorListenerPorts(new PortMapping(ports.get(0), ports.get(1)),
                new PortMapping(ports.get(2), ports.get(3)),
                OptionalInt.of(ports.get(4)));
    }

    // The policy of the bundled tor as TorService renders it, with the torrc of the ports
    private SandyPolicy torPolicy(TorListenerPorts listenerPorts) {
        SandyPolicy policy = TorSandboxPolicy.create(OS.LINUX, directories, listenerPorts, List.of(),
                TorService.sandboxedTorEnvironment(directories), TorSandboxPolicy.executablePaths(OS.LINUX, directories),
                SandboxedTransports.NONE, "bisq2");
        writeTorrc(listenerPorts);
        return policy;
    }

    private SandyPolicy linuxPolicy() throws Exception {
        return renderPolicy(SandboxedTransports.NONE, List.of());
    }

    private SandyPolicy transportsPolicy() throws Exception {
        return transportsPolicy(List.of());
    }

    // obfs4 connects through the egress broker, so its bridges get linux-transports.toml.
    private SandyPolicy transportsPolicy(List<SandyPolicy.ForwardedPort> forwardedPorts) throws Exception {
        Files.createDirectories(directories.getBinaryDirPath());
        return renderPolicy(new SandboxedTransports(Set.of("obfs4"), List.of(TRANSPORT_PROGRAM)), forwardedPorts);
    }

    // The policy of the bundled tor in which busybox runs instead of Tor, assumed enforceable in its base level
    private SandyPolicy renderPolicy(SandboxedTransports transports,
                                     List<SandyPolicy.ForwardedPort> forwardedPorts) throws Exception {
        assumeTrue(Files.isExecutable(BUSYBOX), "No busybox");
        List<Integer> ports = LoopbackPorts.allocate(5);
        egressPort = ports.get(4);
        var listenerPorts = new TorListenerPorts(new PortMapping(ports.get(0), ports.get(1)),
                new PortMapping(ports.get(2), ports.get(3)),
                OptionalInt.of(egressPort));
        Files.writeString(directories.getTorrcPath(), "SocksPort 0\n");
        SandyPolicy policy = TorSandboxPolicy.create(OS.LINUX, directories, listenerPorts, forwardedPorts, Map.of(),
                TorSandboxPolicy.executablePaths(OS.LINUX, directories), transports, "bisq2");
        assumeEnforceable(policy, "base");
        return policy;
    }

    private record ProbeResult(int exitCode, String output) {
    }

    // Runs busybox with the arguments in the base level of the policy, with the command line of TorService.
    private ProbeResult probe(SandyPolicy policy, String... busyboxArguments) throws Exception {
        List<String> program = new ArrayList<>();
        program.add(BUSYBOX.toString());
        program.addAll(List.of(busyboxArguments));
        Sandy sandy = new Sandy(sandyPath, Long.toString(ProcessHandle.current().pid()));
        Files.deleteIfExists(directories.getSandyStatusRecordPath());
        var processBuilder = new ProcessBuilder(sandy.runCommand(policy,
                new Sandy.Level("base", Set.of(Sandy.ENDS_WITH_PARENT)), directories.getSandyStatusRecordPath(),
                program))
                .redirectErrorStream(true);
        Sandy.removeLoaderVariables(processBuilder.environment());
        Process process = processBuilder.start();
        try (OutputStream input = process.getOutputStream()) {
            input.write(Sandy.policyInput(policy));
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(process.waitFor(30, TimeUnit.SECONDS)).isTrue();
        return new ProbeResult(process.exitValue(), output);
    }

    // The first line of a connection to the listener, or nothing if no connection came within 2 seconds
    private static String acceptedLine(ServerSocket listener) {
        try {
            listener.setSoTimeout(2000);
            try (Socket socket = listener.accept()) {
                socket.setSoTimeout(5000);
                var reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                return Optional.ofNullable(reader.readLine()).orElse("");
            }
        } catch (SocketTimeoutException e) {
            return "";
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // sandy check selects the first enforceable level of a policy, and with --level it checks only the named one.
    private void assumeEnforceable(SandyPolicy policy, String levelName) throws Exception {
        Process check = new ProcessBuilder(sandyPath.toString(), "check", "--json", "--policy", "-",
                "--level", levelName, "--", torBinaryPath.toString())
                .redirectErrorStream(true)
                .start();
        try (OutputStream input = check.getOutputStream()) {
            input.write(Sandy.policyInput(policy));
        }
        String output = new String(check.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertThat(check.waitFor(30, TimeUnit.SECONDS)).isTrue();
        assumeTrue(check.exitValue() == 0 && output.contains("\"selected\":\"" + levelName + "\""),
                "This host cannot enforce the level " + levelName + ":\n" + output);
    }

    private void writeTorrc(TorListenerPorts listenerPorts) {
        Map<String, String> torrc = TorrcClientConfigFactory.builder()
                .dataDirPath(directories.getDataDirPath())
                .hashedControlPassword(PasswordDigest.generateDigest())
                .controlPort(listenerPorts.control().innerPort())
                .socksPort(listenerPorts.socks().innerPort())
                .build()
                .torrcClientConfigMap(Map.of());
        torrc.put("MaxMemInQueues", TorMemoryLimit.torrcValue());
        new TorrcFileGenerator(directories.getTorrcPath(), torrc, Set.of()).generate();
    }
}
