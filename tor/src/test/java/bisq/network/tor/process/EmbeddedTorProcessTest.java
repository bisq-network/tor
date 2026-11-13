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

package bisq.network.tor.process;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class EmbeddedTorProcessTest {
    @TempDir
    Path tempDir;

    @Test
    @Timeout(30)
    void aShutdownWaitsForTheChildOfTheLauncher() throws Exception {
        assertShutdownStopsChild(false);
    }

    @Test
    @Timeout(30)
    void aShutdownStillWaitsForCapturedChildrenAfterTheLauncherExits() throws Exception {
        assertShutdownStopsChild(true);
    }

    private void assertShutdownStopsChild(boolean exitLauncherBeforeShutdown) throws Exception {
        Path logPath = tempDir.resolve("tor.log");
        var process = new EmbeddedTorProcess(ProcessTreeFixture.command(tempDir, "launcher"), tempDir,
                environment -> {}, logPath);
        ProcessHandle child = null;
        try {
            process.start();
            awaitFile(tempDir.resolve("child.ready"));
            String[] childInfo = Files.readString(tempDir.resolve("child.ready")).trim().split(" ");
            child = ProcessHandle.of(Long.parseLong(childInfo[0])).orElseThrow();
            int port = Integer.parseInt(childInfo[1]);
            assertThat(child.isAlive()).isTrue();

            if (exitLauncherBeforeShutdown) {
                // Model controller closure ending the launcher before EmbeddedTorProcess.shutdown is called.
                process.captureProcessTree();
                Files.createFile(tempDir.resolve("exit-launcher"));
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                while (process.isAlive() && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
                assertThat(process.isAlive()).isFalse();
                assertThat(child.isAlive()).isTrue();
            }

            process.shutdown();

            assertThat(child.isAlive()).as("The launcher must not leave a running child").isFalse();
            // The child inherited the log handle. Its port and the log must be free for the next start.
            retryUntilReleased(() -> {
                try (var listener = new ServerSocket()) {
                    listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
                }
            });
            retryUntilReleased(() -> Files.delete(logPath));
        } finally {
            if (child != null && child.isAlive()) {
                child.destroyForcibly();
                child.onExit().get(5, TimeUnit.SECONDS);
            }
            process.shutdown();
        }
    }

    /**
     * On Windows, a terminated process reports its exit code before it has closed its handles. Java cannot wait for
     * that for a descendant: in JDK 21, ProcessHandle.isAlive and onExit read the exit code first, and only
     * Process.waitFor of a direct child waits on its handle.
     */
    private static void retryUntilReleased(ReleaseCheck check) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (true) {
            try {
                check.run();
                return;
            } catch (IOException e) {
                if (System.nanoTime() > deadline) {
                    throw e;
                }
                Thread.sleep(50);
            }
        }
    }

    private interface ReleaseCheck {
        void run() throws IOException;
    }

    private static void awaitFile(Path path) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!Files.exists(path) && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertThat(path).exists();
    }

    // A real process tree without Tor or a shell. The child keeps a listener and the inherited logs open.
    public static class ProcessTreeFixture {
        static List<String> command(Path directory, String role) throws Exception {
            String java = Path.of(System.getProperty("java.home"), "bin",
                    System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java").toString();
            String classPath = Path.of(ProcessTreeFixture.class.getProtectionDomain().getCodeSource()
                    .getLocation().toURI()).toString();
            return List.of(java, "-cp", classPath, ProcessTreeFixture.class.getName(), directory.toString(), role);
        }

        public static void main(String[] args) throws Exception {
            Path directory = Path.of(args[0]);
            if (args[1].equals("launcher")) {
                new ProcessBuilder(command(directory, "child")).inheritIO().start();
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
                while (!Files.exists(directory.resolve("exit-launcher")) && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
            } else {
                try (var listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                    Path ready = directory.resolve("child.ready.tmp");
                    Files.writeString(ready, ProcessHandle.current().pid() + " " + listener.getLocalPort());
                    Files.move(ready, directory.resolve("child.ready"));
                    Thread.sleep(60_000);
                }
            }
        }
    }

    @Test
    void theCommandLineWorksWithOlderSystemTors() {
        // --torrc-file exists only since Tor 0.4.6.2-alpha, -f in every version
        assertThat(EmbeddedTorProcess.torCommand(tempDir.resolve("tor"), tempDir.resolve("torrc"), "42"))
                .containsExactly(tempDir.resolve("tor").toString(),
                        "-f", tempDir.resolve("torrc").toString(),
                        "--defaults-torrc", tempDir.resolve("torrc").toString(),
                        "__OwningControllerProcess", "42");
    }

    @Test
    void torRunsInTheGivenWorkingDirectory() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        // Tor finds the programs of the pluggable transports relative to its working directory.
        Path workingDir = Files.createDirectories(tempDir.resolve("Application Support"));
        Path logPath = tempDir.resolve("tor.log");
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", "pwd -P"), workingDir, environment -> {
        }, logPath);

        process.start();
        process.waitUntilExited();

        assertThat(Files.readString(logPath).trim()).isEqualTo(workingDir.toRealPath().toString());
    }

    @Test
    void torRunsInASessionOfItsOwnSoThatCtrlCInTheTerminalOfBisqDoesNotReachIt() throws IOException {
        // The session ID is the sixth field of /proc/<pid>/stat on Linux
        Path jvmStat = Path.of("/proc/self/stat");
        assumeTrue(Files.isReadable(jvmStat));
        assumeTrue(EmbeddedTorProcess.findExecutableInPath(System.getenv("PATH"), "setsid").isPresent());
        Path logPath = tempDir.resolve("tor.log");

        runToCompletion("echo $$ $(cut -d ' ' -f 6 /proc/$$/stat)", logPath);

        String[] pidAndSession = Files.readString(logPath).trim().split(" ");
        assertThat(pidAndSession[1]).isEqualTo(pidAndSession[0]);
        assertThat(pidAndSession[1]).isNotEqualTo(Files.readString(jvmStat).split(" ")[5]);
    }

    @Test
    void setsidPrecedesTheCommandWhereTheSystemHasIt() {
        List<String> command = List.of("/usr/bin/tor", "-f", "torrc");
        Path setsidPath = tempDir.resolve("setsid");

        assertThat(EmbeddedTorProcess.inSessionOfItsOwn(command, Optional.of(setsidPath)))
                .containsExactly(setsidPath.toString(), "/usr/bin/tor", "-f", "torrc");
        assertThat(EmbeddedTorProcess.inSessionOfItsOwn(command, Optional.empty())).isEqualTo(command);
    }

    @Test
    void theLogIsKeptAcrossStartsUpToASizeLimit() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path logPath = tempDir.resolve("tor.log");

        runToCompletion("echo first", logPath);
        runToCompletion("echo second", logPath);
        assertThat(Files.readAllLines(logPath)).containsExactly("first", "second");

        try (RandomAccessFile file = new RandomAccessFile(logPath.toFile(), "rw")) {
            file.setLength(10 * 1024 * 1024 + 1);
        }
        runToCompletion("echo third", logPath);

        assertThat(Files.readAllLines(logPath)).containsExactly("third");
        assertThat(Files.size(tempDir.resolve("tor.log.1"))).isEqualTo(10 * 1024 * 1024 + 1);
    }

    @Test
    void theStandardErrorGoesIntoTheLogInTheOrderOfWriting() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path logPath = tempDir.resolve("tor.log");

        runToCompletion("echo first; echo second >&2; echo third", logPath);

        assertThat(Files.readAllLines(logPath)).containsExactly("first", "second", "third");
    }

    @Test
    void theStartupDiagnosticsQuoteTheLogOfThisStart() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path logPath = tempDir.resolve("tor.log");
        runToCompletion("echo output of the start before", logPath);

        // Tor writes the reason of a failed start to its standard output, sandy writes to the standard error
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c",
                "echo \"[err] Reading config failed\"; echo \"sandy: run failed\" >&2; exit 1"), tempDir,
                environment -> {
                }, logPath);
        process.start();
        process.waitUntilExited();

        assertThat(process.getStartupDiagnostics()).isEqualTo("exitCode=1" +
                ", log=" + logPath.toAbsolutePath() +
                ", log=[err] Reading config failed\nsandy: run failed");
        assertThat(process.getStartupDiagnostics("log (by Tor)"))
                .endsWith(", log (by Tor)=[err] Reading config failed\nsandy: run failed");
    }

    @Test
    void theStartupDiagnosticsQuoteTheWholeLogIfItWasReplacedByAShorterOne() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path logPath = tempDir.resolve("tor.log");
        runToCompletion("echo a long output of the start before", logPath);
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", "exit 1"), tempDir, environment -> {
        }, logPath);
        process.start();
        process.waitUntilExited();

        Files.writeString(logPath, "short");

        assertThat(process.getStartupDiagnostics()).endsWith(", log=short");
    }

    private void runToCompletion(String shellCommand, Path logPath) {
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", shellCommand), tempDir, environment -> {
        }, logPath);
        process.start();
        process.waitUntilExited();
    }

    @Test
    void anUnsetPathFindsNothing() {
        assertThat(EmbeddedTorProcess.findExecutableInPath(null, "tor")).isEmpty();
    }

    @Test
    void onlyAnExecutableFileInAnAbsoluteDirectoryIsFound() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path withDirectory = Files.createDirectories(tempDir.resolve("withDirectory").resolve("tor")).getParent();
        Path withNotExecutableFile = Files.createDirectories(tempDir.resolve("withNotExecutableFile"));
        Files.createFile(withNotExecutableFile.resolve("tor"));
        Path withExecutable = Files.createDirectories(tempDir.resolve("withExecutable"));
        Path executable = Files.createFile(withExecutable.resolve("tor"));
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));

        // An empty entry and "." mean the working directory, "bin" a directory relative to it.
        String path = String.join(File.pathSeparator, "", ".", "bin", withDirectory.toString(),
                withNotExecutableFile.toString(), withExecutable.toString());

        assertThat(EmbeddedTorProcess.findExecutableInPath(path, "tor")).contains(executable);
    }

    @Test
    void relativeEntriesAreIgnored() throws IOException {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        Path relativeDirectory = Path.of("").toAbsolutePath().relativize(Files.createDirectories(tempDir.resolve("relative")));
        Path executable = Files.createFile(tempDir.resolve("relative").resolve("tor"));
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));

        assertThat(EmbeddedTorProcess.findExecutableInPath(relativeDirectory.toString(), "tor")).isEmpty();
    }
}
