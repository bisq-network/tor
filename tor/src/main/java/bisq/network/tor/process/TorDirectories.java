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
import com.google.common.annotations.VisibleForTesting;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * The files of the embedded Tor below the Tor directory of the application ({@code <app data dir>/tor}).
 * <p>
 * Only {@link #dataDirPath} is writable for a sandboxed Tor. Bisq writes everything else, and Tor must not be able to
 * change it: otherwise a compromised Tor could replace a file that Bisq later executes, reads or writes outside the
 * sandbox. The Tor directory can also hold files of the application, for example the onion service key of Bisq 1 in
 * {@code hiddenservice}.
 */
@Getter
@ToString
@EqualsAndHashCode
public final class TorDirectories {
    public static final String EXTERNAL_TOR_CONFIG_FILE_NAME = "external_tor.config";
    public static final String PLUGGABLE_TRANSPORTS_DIR_NAME = "pluggable_transports";
    static final String BINARY_DIR_NAME = "bin";
    static final String DATA_DIR_NAME = "data";
    static final String DATA_MODE_FILE_NAME = "data-mode";
    static final String SANDY_DIR_NAME = "sandy";

    private final Path baseDirPath;
    // The installed files of the Tor expert bundle: binary, libraries, pluggable transports and GeoIP files.
    private final Path binaryDirPath;
    // The DataDirectory of Tor.
    private final Path dataDirPath;
    private final Path torrcPath;
    // The log of Tor: the standard output, to which Tor logs, and the standard error of Tor or of sandy
    private final Path logPath;
    // The sandy binary, outside every path which Tor may write
    private final Path sandyDirPath;
    private final Path externalTorConfigPath;

    public TorDirectories(Path baseDirPath) {
        this.baseDirPath = baseDirPath;
        binaryDirPath = baseDirPath.resolve(BINARY_DIR_NAME);
        dataDirPath = baseDirPath.resolve(DATA_DIR_NAME);
        torrcPath = baseDirPath.resolve("torrc");
        logPath = baseDirPath.resolve("tor.log");
        sandyDirPath = baseDirPath.resolve(SANDY_DIR_NAME);
        externalTorConfigPath = baseDirPath.resolve(EXTERNAL_TOR_CONFIG_FILE_NAME);
    }

    /**
     * @return {@code baseDirPath} with the symbolic links on the way to it resolved, also those on Windows which
     * {@link Path#toRealPath} resolves (junctions among them). The sandbox grants the real path of every policy path, so
     * Tor and the policy name the real paths: sandy before 1.1.0 did not find a path spelled through a symbolic link
     * inside the sandbox of macOS, and on Windows sandy would otherwise add a read entry for the sandbox to each
     * junction of the user on the way to the Tor directory. The Tor directory need not exist yet: its nearest existing ancestor is resolved,
     * and the names below it are kept. Links inside the Tor directory are not resolved here; Bisq creates its entries
     * and treats a link among them as foreign.
     * @throws IOException if the nearest existing ancestor cannot be resolved, for example a link that leads nowhere
     */
    public static Path withLinksResolved(Path baseDirPath) throws IOException {
        Path existing = baseDirPath.toAbsolutePath();
        Deque<Path> missingNames = new ArrayDeque<>();
        // A link counts as existing, also one that leads nowhere, so that toRealPath reports it instead of a directory
        // being created where it lies.
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            Path parent = existing.getParent();
            if (parent == null) {
                return baseDirPath.toAbsolutePath();
            }
            missingNames.push(existing.getFileName());
            existing = parent;
        }
        Path resolved = existing.toRealPath();
        for (Path name : missingNames) {
            resolved = resolved.resolve(name);
        }
        return resolved;
    }

    /**
     * @return the earlier log of Tor, which {@link EmbeddedTorProcess} moves aside when the log exceeds its size limit.
     * An application which shows, backs up or leaves out the logs of Tor takes their paths from here.
     */
    public Path getRotatedLogPath() {
        return EmbeddedTorProcess.rotatedLogPath(logPath);
    }

    /**
     * @return the files and directories of this layout directly in the Tor directory. The Tor directory can also hold
     * files of the application, for example the onion service key of Bisq 1 in {@code hiddenservice}.
     */
    List<Path> getLayoutEntries() {
        return List.of(binaryDirPath, dataDirPath, sandyDirPath, torrcPath, getOpenSslConfigPath(), logPath,
                getRotatedLogPath(), externalTorConfigPath, getDataModePath());
    }

    /**
     * @return the files which earlier versions of this layout wrote and this version does not: up to version 1.0.1,
     * the standard output of Tor went to {@code tor-stdout.log} (moved to {@code tor-stdout.log.1} above the size
     * limit) and the standard error to {@code tor-stderr.log}. {@link #getLogPath()} replaces them.
     */
    List<Path> getObsoleteEntries() {
        Path stdoutLogPath = baseDirPath.resolve("tor-stdout.log");
        return List.of(stdoutLogPath, EmbeddedTorProcess.rotatedLogPath(stdoutLogPath),
                baseDirPath.resolve("tor-stderr.log"));
    }

    // The GeoIP files of the bundled Tor, which the bundle installs next to the binary.
    public Path getBundledGeoIpFilePath() {
        return binaryDirPath.resolve("geoip");
    }

    public Path getBundledGeoIpv6FilePath() {
        return binaryDirPath.resolve("geoip6");
    }

    // An empty OpenSSL configuration for the bundled Tor
    public Path getOpenSslConfigPath() {
        return baseDirPath.resolve("openssl.cnf");
    }

    public Path getPluggableTransportsDirPath() {
        return binaryDirPath.resolve(PLUGGABLE_TRANSPORTS_DIR_NAME);
    }

    // The configuration of the pluggable transports and the built-in bridges of the Tor Browser version of the bundle
    public Path getPluggableTransportConfigPath() {
        return getPluggableTransportsDirPath().resolve("pt_config.json");
    }

    // The status record which sandy writes for each run of a sandboxed Tor, outside every path which Tor may write
    public Path getSandyStatusRecordPath() {
        return sandyDirPath.resolve("run-status");
    }

    // Whether the last Tor which used the data directory ran in the sandbox (TorDataDirectoryMode)
    public Path getDataModePath() {
        return baseDirPath.resolve(DATA_MODE_FILE_NAME);
    }

    public Path getBundledTorBinaryPath() {
        return getBundledTorBinaryPath(OS.isWindows());
    }

    @VisibleForTesting
    Path getBundledTorBinaryPath(boolean isWindows) {
        return binaryDirPath.resolve(isWindows ? "tor.exe" : "tor");
    }
}
