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

import bisq.network.tor.process.EmbeddedTorProcess;
import bisq.network.tor.process.TorStartupFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.FileSystemException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The embedded Tor can exit before it answers on its control port. When sandy started it, the exit can be a refusal of
 * sandy, for example because another process took a port of the policy between the check and the start. Then the user
 * needs the reason of sandy and the hint how to turn the sandbox off, as for every other sandbox failure. Tor can exit
 * with the status of sandy too, so only the status record of sandy, which Tor cannot write, tells a refusal from an
 * exit of Tor. A stand-in for sandy writes the records here as sandy 1.2.0 does.
 */
@Timeout(30)
class TorServiceStartFailureTest {
    private static final String OPT_OUT_HINT = "Start Bisq with the option --useTorSandbox=false";

    @TempDir
    Path tempDir;
    private int closedPort;

    @BeforeEach
    void setUp() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        try (ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            closedPort = serverSocket.getLocalPort();
        }
    }

    @Test
    void aRefusalOfSandyIsASandboxFailureWithTheReasonAndTheHint() {
        EmbeddedTorProcess process = start(writeStatusRecord("level base\\nfailed\\n") +
                "echo 'sandy: run failed: cannot listen on 127.0.0.1:12345: Address in use' >&2; exit 125");

        // A refusal which can pass, which the start tries once more
        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process, sandboxedRun()))
                .isInstanceOf(TorService.SandyRefusalException.class)
                .hasMessageContaining("sandy did not start Tor")
                .hasMessageContaining("statusRecord=[level base, failed]")
                .hasMessageContaining("cannot listen on 127.0.0.1:12345")
                .hasMessageContaining(OPT_OUT_HINT)
                .hasNoCause();
    }

    @Test
    void anExitOfTorInTheSandboxIsAStartFailure() {
        EmbeddedTorProcess process = start(writeStatusRecord("level base\\npid 4711\\n") +
                "echo 'Could not bind to 127.0.0.1:9050' >&2; exit 1");

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process, sandboxedRun()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exited before it answered")
                .hasMessageContaining("Could not bind to 127.0.0.1:9050");
    }

    // A compromised Tor chooses its exit status and its log, but it cannot write the status record.
    @Test
    void aTorWhichExitsWithTheStatusOfSandyGetsNoAdviceToTurnTheSandboxOff() {
        EmbeddedTorProcess process = start(writeStatusRecord("level base\\npid 4711\\n") +
                "echo 'sandy: this system cannot run the sandbox. Turn it off.' >&2; exit 125");

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process, sandboxedRun()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exited before it answered")
                .hasMessageContaining("statusRecord=[level base, pid 4711]")
                .hasMessageNotContaining(OPT_OUT_HINT)
                .satisfies(e -> assertThatTheQuoteIsLabeledAndLast(e.getMessage(),
                        "sandy: this system cannot run the sandbox. Turn it off."));
    }

    // The quote comes last, after the facts which Bisq knows, and says that Tor in its sandbox can have written it.
    @Test
    void theLogOfASandboxedStartIsQuotedAsTextWhichBisqDidNotVerify() {
        EmbeddedTorProcess refused = start(writeStatusRecord("level base\\nfailed\\n") +
                "echo 'sandy: run failed' >&2; exit 125");
        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, refused, sandboxedRun()))
                .isInstanceOf(TorService.SandyRefusalException.class)
                .satisfies(e -> assertThatTheQuoteIsLabeledAndLast(((TorService.SandyRefusalException) e).getReason(),
                        "sandy: run failed"));

        EmbeddedTorProcess exited = start(writeStatusRecord("level base\\npid 4711\\n") +
                "echo 'Could not bind' >&2; exit 1");
        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, exited, sandboxedRun()))
                .satisfies(e -> assertThatTheQuoteIsLabeledAndLast(e.getMessage(), "Could not bind"));
    }

    // Tor writes the reason of a failed start, for example an unknown option of the torrc, to its standard output.
    @Test
    void theReasonWhichTorWritesToItsStandardOutputIsQuoted() {
        EmbeddedTorProcess exited = start(writeStatusRecord("level base\\npid 4711\\nexited 1\\n") +
                "echo \"[err] Reading config failed--see warnings above.\"; exit 1");
        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, exited, sandboxedRun()))
                .hasMessageContaining(", log=" + tempDir.resolve("tor.log").toAbsolutePath())
                .satisfies(e -> assertThatTheQuoteIsLabeledAndLast(e.getMessage(),
                        "[err] Reading config failed--see warnings above."));
    }

    // Without the sandbox Tor has all the rights of Bisq, so a label would add nothing.
    @Test
    void theLogOfAStartWithoutTheSandboxIsQuotedWithoutALabel() {
        EmbeddedTorProcess process = start("echo '[err] Reading config failed'; echo 'Could not bind' >&2; exit 1");

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process, Optional.empty()))
                .hasMessageEndingWith(", log=[err] Reading config failed\nCould not bind")
                .hasMessageNotContaining("not verified");
    }

    private static void assertThatTheQuoteIsLabeledAndLast(String message, String quote) {
        String label = "log (written by sandy and by Tor in its sandbox, not verified by Bisq)=";
        assertThat(message).endsWith(label + quote);
        assertThat(message.indexOf("exitCode=")).isLessThan(message.indexOf(label));
        assertThat(message.indexOf("statusRecord=")).isLessThan(message.indexOf(label));
    }

    // Where sandy stays the parent of Tor, it writes the process ID once Tor runs, so a failure after it is no refusal.
    @Test
    void aFailureOfSandyAfterTorRanGetsNoAdviceToTurnTheSandboxOff() {
        EmbeddedTorProcess process = start(writeStatusRecord("level contained\\npid 4711\\nfailed\\n") + "exit 125");

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process,
                Optional.of(new TorService.SandboxedRun(statusRecordPath(), true, OPT_OUT_HINT))))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("statusRecord=[level contained, pid 4711, failed]");
    }

    @Test
    void theStatusRecordIsRemovedOnceItIsRead() {
        EmbeddedTorProcess process = start(writeStatusRecord("level base\\npid 4711\\n") + "exit 1");

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process, sandboxedRun()))
                .isInstanceOf(IOException.class);
        assertThat(statusRecordPath()).doesNotExist();
    }

    @Test
    void anExitWithTheStatusOfSandyWithoutTheSandboxIsAStartFailure() {
        EmbeddedTorProcess process = start("exit 125");

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process, Optional.empty()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("exited before it answered");
    }

    // sandy passes the 32-bit exit code of tor.exe on unchanged, and Java reports 0xC0000142 as a negative int.
    @Test
    void aFailedDllInitializationOfTorOnWindowsNamesTheSessionAsTheLikelyCause() {
        assertThat(TorService.windowsSessionHint(Optional.of(0xC0000142)))
                .contains("STATUS_DLL_INIT_FAILED")
                .contains("window station");
        assertThat(TorService.windowsSessionHint(Optional.of(1))).isEmpty();
        assertThat(TorService.windowsSessionHint(Optional.empty())).isEmpty();
    }

    // sandy refuses an argument before it reads the policy, so the write of the policy fails with a broken pipe. It
    // also stops before it creates the status record.
    @Test
    void aSandyWhichEndsBeforeItReadsThePolicyIsASandboxFailureWithItsReason() {
        // Larger than a pipe buffer, so that the write fails once the process has ended
        byte[] policy = new byte[1024 * 1024];
        EmbeddedTorProcess process = start("echo 'sandy: unknown option --frobnicate' >&2; exit 125",
                Optional.of(policy));

        assertThatThrownBy(() -> TorService.waitUntilControlPortAnswers(closedPort, process, sandboxedRun()))
                .isInstanceOf(TorService.SandyRefusalException.class)
                .hasMessageContaining("statusRecord=[none]")
                .hasMessageContaining("unknown option --frobnicate")
                .hasMessageContaining(OPT_OUT_HINT);
    }

    // Bisq 2 shows only the root cause of a failed start, so the exception which names the reason has no cause.
    @Test
    void aFailureToCreateTheTorDirectoryIsTheRootCause() throws IOException {
        Path torDir = Files.writeString(tempDir.resolve("tor"), "a file instead of the Tor directory");

        // TorService names the real path, which on macOS differs from that of the temporary directory (/private/var).
        assertThatThrownBy(() -> createTorService(torDir).initialize())
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("Couldn't create the Tor directory " + torDir.toRealPath())
                .hasNoCause();
    }

    @Test
    void aFailureToReadTheExternalTorConfigurationIsTheRootCause() throws IOException {
        Path torDir = Files.createDirectories(tempDir.resolve("tor"));
        Files.createDirectories(torDir.resolve("external_tor.config"));

        assertThatThrownBy(() -> createTorService(torDir).initialize())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Could not read " + torDir.toRealPath().resolve("external_tor.config"))
                .hasNoCause();
    }

    @Test
    void aFailureToWriteTheConfigurationOfOpenSslNamesItsReason() throws Exception {
        Path torDir = Files.createDirectories(tempDir.resolve("tor"));
        // The start does not install the bundle of the jar over the fake one.
        try (FakeBundledTor ignored = FakeBundledTor.install(torDir)) {
            Files.createDirectories(torDir.resolve("openssl.cnf"));

            assertThatThrownBy(() -> createTorService(torDir).initialize())
                    .isInstanceOf(TorStartupFailedException.class)
                    .hasMessage("Couldn't write openssl.cnf")
                    .hasCauseInstanceOf(FileSystemException.class);
        }
    }

    @Test
    void aProgramWhichCannotStartIsTheRootCause() {
        var process = new EmbeddedTorProcess(List.of(tempDir.resolve("missing").toString()), tempDir.resolve("missing"),
                environment -> {
                }, tempDir.resolve("tor.log"));

        assertThatThrownBy(process::start)
                .isInstanceOf(TorStartupFailedException.class)
                .hasMessageContaining("Could not start")
                .hasNoCause();
    }

    private static TorService createTorService(Path torDir) {
        var transportConfig = new TorTransportConfig(torDir, 1000, 1000, false, Set.of(), Map.of(), false);
        return new TorService(transportConfig, new PlatformServices() {
            @Override
            public String getMyPid() {
                return String.valueOf(ProcessHandle.current().pid());
            }

            @Override
            public Stream<String> getProcessCommandStream() {
                return Stream.empty();
            }

            @Override
            public boolean supportsPosixPermissions() {
                return true;
            }
        }, false);
    }

    // In the level base of linux.toml sandy replaces itself with Tor.
    private Optional<TorService.SandboxedRun> sandboxedRun() {
        return Optional.of(new TorService.SandboxedRun(statusRecordPath(), false, OPT_OUT_HINT));
    }

    private Path statusRecordPath() {
        return tempDir.resolve("run-status");
    }

    // A shell command which writes the record as sandy does, with \n for the line ends
    private String writeStatusRecord(String content) {
        return "printf '" + content + "' > '" + statusRecordPath() + "'; ";
    }

    private EmbeddedTorProcess start(String shellCommand) {
        return start(shellCommand, Optional.empty());
    }

    private EmbeddedTorProcess start(String shellCommand, Optional<byte[]> standardInput) {
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", shellCommand), tempDir, environment -> {
        }, tempDir.resolve("tor.log"), standardInput);
        process.start();
        process.waitUntilExited();
        return process;
    }
}
