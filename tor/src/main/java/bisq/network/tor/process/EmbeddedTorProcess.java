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

import bisq.network.tor.common.platform.OS;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * The process of the embedded Tor, or of sandy, which starts Tor in the sandbox. Internal: like the other classes which
 * start and run the process of Tor, it is no API of the Tor build, so its constructors and methods may change in any
 * version without notice. Applications start and stop Tor with {@link bisq.network.tor.TorService}; the README names
 * the supported API.
 */
@Slf4j
public class EmbeddedTorProcess {
    public static final String ARG_OWNER_PID = "__OwningControllerProcess";
    private static final int MAX_LOG_SNIPPET_BYTES = 4096;
    // Above this size, the log of the last starts is moved to a single backup before the next start.
    private static final long MAX_STDOUT_LOG_BYTES = 10 * 1024 * 1024;

    private final List<String> command;
    private final Path workingDirPath;
    private final Consumer<Map<String, String>> environmentAdjuster;
    private final Path stdoutLogPath;
    private final Path stderrLogPath;
    // Written to the standard input of the process, which is then closed: the sandy policy of a sandboxed Tor
    private final Optional<byte[]> standardInput;
    private Optional<Process> process = Optional.empty();
    private List<ProcessHandle> shutdownProcessTree = List.of();

    /**
     * @param workingDirPath      the directory of the bundle, so that Tor finds the programs of the pluggable
     *                            transports with the relative paths of the torrc
     * @param environmentAdjuster changes the environment that the process inherits from Bisq
     */
    public EmbeddedTorProcess(List<String> command,
                              Path workingDirPath,
                              Consumer<Map<String, String>> environmentAdjuster,
                              Path stdoutLogPath,
                              Path stderrLogPath) {
        this(command, workingDirPath, environmentAdjuster, stdoutLogPath, stderrLogPath, Optional.empty());
    }

    /**
     * @param standardInput written to the standard input of the process, which is then closed. sandy reads its
     *                      policy there ({@code --policy -}) and gives the program the null device instead. If the
     *                      process ends before it read the input, {@link #start} returns, and its exit status and
     *                      standard error tell why.
     */
    public EmbeddedTorProcess(List<String> command,
                              Path workingDirPath,
                              Consumer<Map<String, String>> environmentAdjuster,
                              Path stdoutLogPath,
                              Path stderrLogPath,
                              Optional<byte[]> standardInput) {
        this.command = List.copyOf(command);
        this.workingDirPath = workingDirPath;
        this.environmentAdjuster = environmentAdjuster;
        this.stdoutLogPath = stdoutLogPath;
        this.stderrLogPath = stderrLogPath;
        this.standardInput = standardInput.map(byte[]::clone);
    }

    /**
     * The command line of Tor itself. Tor exits when the process {@code ownerPid} ends, until its controller resets
     * the option.
     */
    public static List<String> torCommand(Path torBinaryPath, Path torrcPath, String ownerPid) {
        List<String> command = new ArrayList<>(torCommand(torBinaryPath, torrcPath));
        command.add(ARG_OWNER_PID);
        command.add(ownerPid);
        return List.copyOf(command);
    }

    /**
     * The command line of Tor without an owner process, for a Tor which another process ends when Bisq ends.
     */
    public static List<String> torCommand(Path torBinaryPath, Path torrcPath) {
        String absoluteTorrcPathAsString = torrcPath.toAbsolutePath().toString();
        // -f instead of --torrc-file, which Tor only knows since 0.4.6.2-alpha
        return List.of(torBinaryPath.toAbsolutePath().toString(),
                "-f", absoluteTorrcPathAsString,
                "--defaults-torrc", absoluteTorrcPathAsString);
    }

    public void start() {
        Optional<Path> setsidPath = OS.isWindows() ? Optional.empty() : findExecutableInPath(System.getenv("PATH"),
                "setsid");
        var processBuilder = new ProcessBuilder(inSessionOfItsOwn(command, setsidPath));
        processBuilder.directory(workingDirPath.toFile());
        environmentAdjuster.accept(processBuilder.environment());
        processBuilder.redirectError(stderrLogPath.toFile());
        // The log of Tor. It is kept across starts, up to a size limit.
        rotateStdoutLogIfTooLarge();
        processBuilder.redirectOutput(ProcessBuilder.Redirect.appendTo(stdoutLogPath.toFile()));

        Process torProcess;
        try {
            torProcess = processBuilder.start();
        } catch (IOException e) {
            String program = processBuilder.command().get(0);
            log.warn("Could not start {}", program, e);
            throw new TorStartupFailedException("Could not start " + program + ": " + e);
        }
        process = Optional.of(torProcess);
        shutdownProcessTree = List.of();
        standardInput.ifPresent(input -> writeStandardInput(torProcess, input));
    }

    /**
     * A process which ends before it read its whole input, for example sandy, which refused an argument, makes the
     * write fail with a broken pipe. The exit status and the standard error of the process tell why
     * ({@link #getStartupDiagnostics}), so the caller reports the ended process instead of the failed write.
     */
    private static void writeStandardInput(Process process, byte[] input) {
        try (OutputStream outputStream = process.getOutputStream()) {
            outputStream.write(input);
        } catch (IOException e) {
            log.warn("Could not write the standard input of the process: {}", e.getMessage());
        }
    }

    /**
     * On Linux and macOS a child process is in the process group of Bisq. A Ctrl+C in the terminal of Bisq would then
     * also reach Tor, or sandy, which forwards it, and Tor would exit at once, before the shutdown of Bisq has used it,
     * for example to remove the offers of the user. setsid starts the command in a session of its own and executes it
     * in its own process, which it does not fork as the child of Bisq is no group leader, so the process stays the one
     * which Bisq stops. macOS has no setsid; there the command stays in the process group of Bisq.
     */
    static List<String> inSessionOfItsOwn(List<String> command, Optional<Path> setsidPath) {
        if (setsidPath.isEmpty()) {
            return command;
        }
        List<String> sessionCommand = new ArrayList<>();
        sessionCommand.add(setsidPath.get().toAbsolutePath().toString());
        sessionCommand.addAll(command);
        return sessionCommand;
    }

    /**
     * @return the file next to the log of Tor to which the log is moved before a start when it exceeds its size limit
     */
    public static Path rotatedStdoutLogPath(Path stdoutLogPath) {
        return stdoutLogPath.resolveSibling(stdoutLogPath.getFileName() + ".1");
    }

    private void rotateStdoutLogIfTooLarge() {
        try {
            if (Files.isRegularFile(stdoutLogPath, LinkOption.NOFOLLOW_LINKS) &&
                    Files.size(stdoutLogPath) > MAX_STDOUT_LOG_BYTES) {
                Path backupPath = rotatedStdoutLogPath(stdoutLogPath);
                Files.move(stdoutLogPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            log.warn("Could not move the Tor log {} to a backup", stdoutLogPath, e);
        }
    }

    public void waitUntilExited() {
        log.info("Wait until tor process has exited");
        process.ifPresent(process -> {
            try {
                boolean isSuccess = process.waitFor(5, TimeUnit.SECONDS);
                if (!isSuccess) {
                    throw new CouldNotWaitForTorShutdownException("Tor process has not exited after 5 seconds.");
                } else {
                    log.info("Tor process has exited successfully");
                }
            } catch (InterruptedException e) {
                log.warn("Thread got interrupted at waitUntilExited method", e);
                Thread.currentThread().interrupt(); // Restore interrupted state
                throw new CouldNotWaitForTorShutdownException(e);
            }
        });
    }

    public void shutdown() {
        process.ifPresent(process -> {
            List<ProcessHandle> tree = Stream.concat(shutdownProcessTree.stream(),
                    Stream.concat(Stream.of(process.toHandle()), process.descendants())).distinct().toList();
            if (process.isAlive()) process.destroy();
            try {
                if (process.isAlive() && !process.waitFor(3, TimeUnit.SECONDS)) process.destroyForcibly();
                awaitExit(tree, 3);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new CouldNotWaitForTorShutdownException(e);
            } catch (TimeoutException e) {
                tree.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
                try {
                    awaitExit(tree, 3);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new CouldNotWaitForTorShutdownException(interrupted);
                } catch (TimeoutException timeout) {
                    throw new CouldNotWaitForTorShutdownException("Tor or sandy subprocess did not exit after shutdown: " +
                            tree.stream().filter(ProcessHandle::isAlive).map(ProcessHandle::pid).toList());
                }
            }
        });
    }

    /** Snapshot before the controller closes: that close can make sandy exit before its children do. */
    public void prepareForShutdown() {
        if (shutdownProcessTree.isEmpty()) {
            process.ifPresent(process -> shutdownProcessTree = Stream.concat(Stream.of(process.toHandle()),
                    process.descendants()).toList());
        }
    }

    private static void awaitExit(List<ProcessHandle> tree, int seconds)
            throws InterruptedException, TimeoutException {
        try {
            CompletableFuture.allOf(tree.stream().map(ProcessHandle::onExit)
                    .toArray(CompletableFuture[]::new)).get(seconds, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw new CouldNotWaitForTorShutdownException(e);
        }
    }

    public boolean isAlive() {
        return process.map(Process::isAlive).orElse(false);
    }

    public Optional<Integer> getExitCode() {
        return process.flatMap(process -> {
            if (process.isAlive()) {
                return Optional.empty();
            }
            return Optional.of(process.exitValue());
        });
    }

    public String getStartupDiagnostics() {
        return getStartupDiagnostics("stderr");
    }

    /**
     * @param stderrLabel introduces the end of the standard error log, which the diagnostics quote last, for example
     *                    to say who wrote it where the caller cannot vouch for its content
     */
    public String getStartupDiagnostics(String stderrLabel) {
        String exitCode = getExitCode()
                .map(String::valueOf)
                .orElseGet(() -> isAlive() ? "still running" : "not started");
        return "exitCode=" + exitCode +
                ", stderrLog=" + stderrLogPath.toAbsolutePath() +
                ", " + stderrLabel + "=" + readLogSnippet(stderrLogPath);
    }

    /**
     * @param pathEnvironmentVariable the value of PATH, or null if it is not set
     */
    public static Optional<Path> findExecutableInPath(String pathEnvironmentVariable, String fileName) {
        if (pathEnvironmentVariable == null) {
            return Optional.empty();
        }
        for (String entry : pathEnvironmentVariable.split(File.pathSeparator)) {
            // An empty or relative entry means a path relative to the working directory of Bisq. A file there must
            // not be started instead of the program of the system.
            Optional<Path> directory = toAbsolutePath(entry);
            if (directory.isPresent()) {
                Path candidate = directory.get().resolve(fileName);
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                    return Optional.of(candidate);
                }
            }
        }
        return Optional.empty();
    }

    private static Optional<Path> toAbsolutePath(String pathEntry) {
        if (pathEntry.isBlank()) {
            return Optional.empty();
        }
        try {
            Path path = Paths.get(pathEntry);
            return path.isAbsolute() ? Optional.of(path) : Optional.empty();
        } catch (InvalidPathException e) {
            return Optional.empty();
        }
    }

    private String readLogSnippet(Path logPath) {
        try {
            if (!Files.exists(logPath)) {
                return "<missing>";
            }
            long fileSize = Files.size(logPath);
            int bytesToRead = (int) Math.min(fileSize, MAX_LOG_SNIPPET_BYTES);
            ByteBuffer buffer = ByteBuffer.allocate(bytesToRead);
            try (var channel = Files.newByteChannel(logPath, StandardOpenOption.READ)) {
                channel.position(Math.max(0, fileSize - bytesToRead));
                while (buffer.hasRemaining() && channel.read(buffer) != -1) {
                    // Read until the requested tail buffer is filled or EOF is reached.
                }
            }
            buffer.flip();
            String content = StandardCharsets.UTF_8.decode(buffer).toString().trim();
            return content.isEmpty() ? "<empty>" : content;
        } catch (IOException e) {
            return "<failed to read " + logPath.toAbsolutePath() + ": " + e.getMessage() + ">";
        }
    }
}
