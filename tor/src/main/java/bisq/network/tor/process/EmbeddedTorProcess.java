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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

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
    private static final long MAX_LOG_BYTES = 10 * 1024 * 1024;

    private final List<String> command;
    private final Path workingDirPath;
    private final Consumer<Map<String, String>> environmentAdjuster;
    // The standard output and the standard error of the process, in the order in which it wrote them
    private final Path logPath;
    // Written to the standard input of the process, which is then closed: the sandy policy of a sandboxed Tor
    private final Optional<byte[]> standardInput;
    private volatile Optional<Process> process = Optional.empty();
    // The size of the log before this start, where the output of this start begins
    private volatile long logStartPosition;
    private final Set<ProcessHandle> descendants = ConcurrentHashMap.newKeySet();

    /**
     * @param workingDirPath      the directory of the bundle, so that Tor finds the programs of the pluggable
     *                            transports with the relative paths of the torrc
     * @param environmentAdjuster changes the environment that the process inherits from Bisq
     */
    public EmbeddedTorProcess(List<String> command,
                              Path workingDirPath,
                              Consumer<Map<String, String>> environmentAdjuster,
                              Path logPath) {
        this(command, workingDirPath, environmentAdjuster, logPath, Optional.empty());
    }

    /**
     * @param standardInput written to the standard input of the process, which is then closed. sandy reads its
     *                      policy there ({@code --policy -}) and gives the program the null device instead. If the
     *                      process ends before it read the input, {@link #start} returns, and its exit status and
     *                      log tell why.
     */
    public EmbeddedTorProcess(List<String> command,
                              Path workingDirPath,
                              Consumer<Map<String, String>> environmentAdjuster,
                              Path logPath,
                              Optional<byte[]> standardInput) {
        this.command = List.copyOf(command);
        this.workingDirPath = workingDirPath;
        this.environmentAdjuster = environmentAdjuster;
        this.logPath = logPath;
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
        // Tor logs to its standard output. sandy, and the system when it cannot start a program, write to the standard
        // error. One file keeps both in the order in which they were written. It is kept across starts, up to a size
        // limit.
        rotateLogIfTooLarge();
        logStartPosition = sizeOrZero(logPath);
        processBuilder.redirectErrorStream(true);
        processBuilder.redirectOutput(ProcessBuilder.Redirect.appendTo(logPath.toFile()));

        Process torProcess;
        try {
            torProcess = processBuilder.start();
        } catch (IOException e) {
            String program = processBuilder.command().get(0);
            log.warn("Could not start {}", program, e);
            throw new TorStartupFailedException("Could not start " + program + ": " + e);
        }
        process = Optional.of(torProcess);
        standardInput.ifPresent(input -> writeStandardInput(torProcess, input));
    }

    /**
     * A process which ends before it read its whole input, for example sandy, which refused an argument, makes the
     * write fail with a broken pipe. The exit status and the log of the process tell why
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
    public static Path rotatedLogPath(Path logPath) {
        return logPath.resolveSibling(logPath.getFileName() + ".1");
    }

    private void rotateLogIfTooLarge() {
        try {
            if (Files.isRegularFile(logPath, LinkOption.NOFOLLOW_LINKS) &&
                    Files.size(logPath) > MAX_LOG_BYTES) {
                Path backupPath = rotatedLogPath(logPath);
                Files.move(logPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            log.warn("Could not move the Tor log {} to a backup", logPath, e);
        }
    }

    private static long sizeOrZero(Path path) {
        try {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ? Files.size(path) : 0;
        } catch (IOException e) {
            return 0;
        }
    }

    /**
     * Retains handles while the tree is still intact. In particular, call this before closing the controller:
     * sandy can exit before its descendants, after which they can no longer be found through the launcher.
     */
    public void captureProcessTree() {
        process.ifPresent(parent -> {
            try (var children = parent.descendants()) {
                children.forEach(descendants::add);
            }
        });
        // A previously captured child can have children of its own even after the launcher has exited.
        for (ProcessHandle descendant : List.copyOf(descendants)) {
            try (var children = descendant.descendants()) {
                children.forEach(descendants::add);
            }
        }
    }

    private List<ProcessHandle> managedProcesses() {
        captureProcessTree();
        List<ProcessHandle> processes = new ArrayList<>(descendants);
        // Signal children first so that the launcher can still reap them.
        process.ifPresent(parent -> processes.add(parent.toHandle()));
        return processes;
    }

    public void waitUntilExited() {
        log.info("Wait until tor process has exited");
        try {
            if (!waitForExit(managedProcesses(), System.nanoTime() + TimeUnit.SECONDS.toNanos(5))) {
                throw new CouldNotWaitForTorShutdownException("Tor process tree has not exited after 5 seconds.");
            }
            log.info("Tor process tree has exited successfully");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CouldNotWaitForTorShutdownException(e);
        }
    }

    public void shutdown() {
        shutdownProcesses(managedProcesses());
    }

    static void shutdownProcesses(List<ProcessHandle> processes) {
        boolean interrupted = Thread.interrupted();
        try {
            destroyProcesses(processes, false);
            if (!interrupted) {
                try {
                    if (waitForExit(processes, System.nanoTime() + TimeUnit.SECONDS.toNanos(3))) {
                        return;
                    }
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            destroyProcesses(processes, true);
            // An interruption must not leave descendants running. Keep the original bound across interruptions.
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (true) {
                try {
                    if (!waitForExit(processes, deadline)) {
                        List<Long> remaining = processes.stream().filter(ProcessHandle::isAlive)
                                .map(ProcessHandle::pid).toList();
                        throw new CouldNotWaitForTorShutdownException(
                                "Tor processes did not exit after termination: " + remaining);
                    }
                    return;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void destroyProcesses(List<ProcessHandle> processes, boolean forcibly) {
        for (ProcessHandle process : processes) {
            if (process.isAlive()) {
                try {
                    if (forcibly) {
                        process.destroyForcibly();
                    } else {
                        process.destroy();
                    }
                } catch (RuntimeException e) {
                    // Still attempt every other process, then report any survivors after the bounded wait.
                    log.warn("Could not terminate Tor process {}", process.pid(), e);
                }
            }
        }
    }

    private static boolean waitForExit(List<ProcessHandle> processes, long deadline) throws InterruptedException {
        while (processes.stream().anyMatch(ProcessHandle::isAlive)) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                return false;
            }
            TimeUnit.NANOSECONDS.sleep(Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(10)));
        }
        return true;
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
        return getStartupDiagnostics("log");
    }

    /**
     * The diagnostics name the log and quote its end after the facts which Bisq knows itself. The log holds the reason
     * of a failed start: Tor logs to its standard output, and sandy and the system write to the standard error. The
     * quote covers only the output of this start, because the log is kept across starts.
     *
     * @param logLabel introduces the quote of the log, for example to say who wrote it where the caller cannot vouch
     *                 for its content
     */
    public String getStartupDiagnostics(String logLabel) {
        String exitCode = getExitCode()
                .map(String::valueOf)
                .orElseGet(() -> isAlive() ? "still running" : "not started");
        return "exitCode=" + exitCode +
                ", log=" + logPath.toAbsolutePath() +
                ", " + logLabel + "=" + readLogSnippet(logPath, logStartPosition);
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

    /**
     * @param startPosition where the part to quote begins. If the file is shorter, it was replaced, and the quote
     *                      begins at its start.
     */
    private static String readLogSnippet(Path logPath, long startPosition) {
        try {
            if (!Files.exists(logPath)) {
                return "<missing>";
            }
            long fileSize = Files.size(logPath);
            long start = startPosition <= fileSize ? startPosition : 0;
            int bytesToRead = (int) Math.min(fileSize - start, MAX_LOG_SNIPPET_BYTES);
            ByteBuffer buffer = ByteBuffer.allocate(bytesToRead);
            try (var channel = Files.newByteChannel(logPath, StandardOpenOption.READ)) {
                channel.position(fileSize - bytesToRead);
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
