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
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Timeout;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class EmbeddedTorProcessTest {
    @TempDir
    Path tempDir;

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
        Path stdoutLogPath = tempDir.resolve("stdout.log");
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", "pwd -P"), workingDir, environment -> {
        }, stdoutLogPath, tempDir.resolve("stderr.log"));

        process.start();
        process.waitUntilExited();

        assertThat(Files.readString(stdoutLogPath).trim()).isEqualTo(workingDir.toRealPath().toString());
    }

    @Test
    void torRunsInASessionOfItsOwnSoThatCtrlCInTheTerminalOfBisqDoesNotReachIt() throws IOException {
        // The session ID is the sixth field of /proc/<pid>/stat on Linux
        Path jvmStat = Path.of("/proc/self/stat");
        assumeTrue(Files.isReadable(jvmStat));
        assumeTrue(EmbeddedTorProcess.findExecutableInPath(System.getenv("PATH"), "setsid").isPresent());
        Path stdoutLogPath = tempDir.resolve("tor-stdout.log");

        runToCompletion("echo $$ $(cut -d ' ' -f 6 /proc/$$/stat)", stdoutLogPath);

        String[] pidAndSession = Files.readString(stdoutLogPath).trim().split(" ");
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
        Path stdoutLogPath = tempDir.resolve("tor-stdout.log");

        runToCompletion("echo first", stdoutLogPath);
        runToCompletion("echo second", stdoutLogPath);
        assertThat(Files.readAllLines(stdoutLogPath)).containsExactly("first", "second");

        try (RandomAccessFile file = new RandomAccessFile(stdoutLogPath.toFile(), "rw")) {
            file.setLength(10 * 1024 * 1024 + 1);
        }
        runToCompletion("echo third", stdoutLogPath);

        assertThat(Files.readAllLines(stdoutLogPath)).containsExactly("third");
        assertThat(Files.size(tempDir.resolve("tor-stdout.log.1"))).isEqualTo(10 * 1024 * 1024 + 1);
    }

    private void runToCompletion(String shellCommand, Path stdoutLogPath) {
        var process = new EmbeddedTorProcess(List.of("/bin/sh", "-c", shellCommand), tempDir, environment -> {
        }, stdoutLogPath, tempDir.resolve("tor-stderr.log"));
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

    @Test
    @Timeout(20)
    void shutdownWaitsForSandboxChildAfterLauncherExits() throws Exception {
        assumeTrue(System.getProperty("os.name").toLowerCase().contains("win"));
        Path marker = tempDir.resolve("child.pid");
        Path release = tempDir.resolve("release");
        String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
        String classPath = Path.of(ChildProcess.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        var launcher = new EmbeddedTorProcess(List.of(java, "-cp", classPath,
                ChildProcess.class.getName(), "parent", marker.toString(), release.toString()),
                tempDir, environment -> {}, tempDir.resolve("stdout.log"), tempDir.resolve("stderr.log"));
        launcher.start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!Files.exists(marker) && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertThat(Files.exists(marker)).isTrue();
        long childPid = Long.parseLong(Files.readString(marker));
        ProcessHandle child = ProcessHandle.of(childPid).orElseThrow();
        CompletableFuture<Void> stopped = CompletableFuture.runAsync(launcher::shutdown);
        try {
            assertThatThrownBy(() -> stopped.get(250, TimeUnit.MILLISECONDS))
                    .isInstanceOf(TimeoutException.class);
            assertThat(child.isAlive()).isTrue();
            Files.createFile(release);
            stopped.get(10, TimeUnit.SECONDS);
            assertThat(child.isAlive()).isFalse();
            assertThat(launcher.isAlive()).isFalse();
            launcher.shutdown();
        } finally {
            if (!Files.exists(release)) Files.createFile(release);
            child.destroyForcibly();
            stopped.get(10, TimeUnit.SECONDS);
        }
    }

    public static class ChildProcess {
        public static void main(String[] args) throws Exception {
            Path marker = Path.of(args[1]);
            Path release = Path.of(args[2]);
            if (args[0].equals("parent")) {
                String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
                String classPath = Path.of(ChildProcess.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
                Process child = new ProcessBuilder(java, "-cp", classPath,
                        ChildProcess.class.getName(), "child", marker.toString(), release.toString())
                        .inheritIO().start();
                Files.writeString(marker, Long.toString(child.pid()));
                child.waitFor();
            } else {
                while (!Files.exists(release)) Thread.sleep(20);
            }
        }
    }
}
