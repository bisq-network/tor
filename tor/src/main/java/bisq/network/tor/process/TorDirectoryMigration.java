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

import bisq.network.tor.common.file.FileUtils;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Moves an installation from the layout before the sandbox to the layout of {@link TorDirectories}.
 * <p>
 * Before, the Tor directory was the DataDirectory of Tor and also held the bundled Tor, its libraries and pluggable
 * transports, the torrc and the logs. It can also hold files of the application, such as the onion service key of
 * Bisq 1 in {@code hiddenservice}, files which earlier versions left behind, and files of the user. The migration
 * therefore decides by what it knows: it moves the Tor state which it recognizes (the entry guards in {@code state} and
 * the cached directory documents) into the data directory, deletes the files of the old layout which it recognizes,
 * and keeps everything else. The bundle is installed again into the binary directory.
 * <p>
 * The data directory marks a finished migration. The migration collects the Tor state in a temporary directory and
 * renames it to the data directory as its last step, so a migration that was interrupted runs again at the next start.
 * The step is idempotent: after the application deleted the data directory, it finds nothing to move and nothing which
 * the application owns to delete.
 * <p>
 * Files which an earlier version of the new layout wrote and this version does not are removed at every start
 * ({@link #removeObsoleteEntries}). Deleting a missing file changes nothing, so no record of a done removal is needed.
 */
@Slf4j
public final class TorDirectoryMigration {
    static final String MIGRATION_DIR_NAME = "data.migration";
    // The files which Tor wrote into its old DataDirectory and creates again in the data directory
    private static final Set<String> OLD_TOR_RUNTIME_NAMES = Set.of("lock", "control", "debug.log", "keys",
            "diff-cache", "pt_state", "control_auth_cookie", ".tor", "pid");
    private static final String OLD_TOR_RUNTIME_PREFIX = "unverified-";
    // The marker of the old installation of the bundle
    private static final String OLD_INSTALLATION_VERSION_FILE_NAME = "version";

    private TorDirectoryMigration() {
    }

    /**
     * The names of the files and directories which the bundle installed into the Tor directory of the old layout. They
     * come from the Tor bundle of the jar, which a reader inflates in full.
     */
    @FunctionalInterface
    public interface BundleNamesReader {
        Set<String> read() throws IOException;
    }

    /**
     * @param oldBundleNames the names of the files and directories which the bundle installed into the Tor directory
     *                       of the old layout
     */
    public static void migrateIfNeeded(TorDirectories directories, Set<String> oldBundleNames) throws IOException {
        migrateIfNeeded(directories, () -> oldBundleNames);
    }

    /**
     * @param bundleNamesReader reads the names of the old bundle, only if a migration runs, so not at every start
     */
    public static void migrateIfNeeded(TorDirectories directories,
                                       BundleNamesReader bundleNamesReader) throws IOException {
        Path dataDirPath = directories.getDataDirPath();
        if (Files.isDirectory(dataDirPath, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Set<String> oldBundleNames = bundleNamesReader.read();

        Path baseDirPath = directories.getBaseDirPath();
        FileUtils.createDirectories(baseDirPath);
        Path migrationDirPath = baseDirPath.resolve(MIGRATION_DIR_NAME);
        if (!Files.isDirectory(migrationDirPath, LinkOption.NOFOLLOW_LINKS)) {
            FileUtils.deleteRecursively(migrationDirPath);
            FileUtils.createDirectories(migrationDirPath);
        }

        List<Path> entries;
        try (Stream<Path> stream = Files.list(baseDirPath)) {
            entries = stream.collect(Collectors.toList());
        }
        Set<String> newLayoutNames = newLayoutNames(directories);
        for (Path entry : entries) {
            String name = entry.getFileName().toString();
            if (isTorState(entry)) {
                moveTorState(entry, migrationDirPath.resolve(name));
            } else if (isOldLayoutFile(name, oldBundleNames)) {
                deleteQuietly(entry);
            } else if (!newLayoutNames.contains(name)) {
                log.info("The Tor directory keeps {}, which the Tor library does not know", entry.toAbsolutePath());
            }
        }

        // A link or a file at the path of the data directory is not part of any layout.
        FileUtils.deleteRecursively(dataDirPath);
        Files.move(migrationDirPath, dataDirPath, StandardCopyOption.ATOMIC_MOVE);
        log.info("The Tor directory {} has separate binary and data directories now", baseDirPath.toAbsolutePath());
    }

    /**
     * Deletes the files which earlier versions of the layout wrote and this version does not. A directory at such a
     * path is not a file of an earlier version, so it is kept. A symbolic link is deleted, not its target.
     */
    public static void removeObsoleteEntries(TorDirectories directories) {
        for (Path entry : directories.getObsoleteEntries()) {
            if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                log.info("The Tor directory keeps the directory {}, which the Tor library does not know",
                        entry.toAbsolutePath());
                continue;
            }
            try {
                Files.deleteIfExists(entry);
            } catch (IOException e) {
                log.warn("Could not delete {} of an earlier version of the Tor library", entry.toAbsolutePath(), e);
            }
        }
    }

    private static boolean isTorState(Path entry) {
        String name = entry.getFileName().toString();
        return Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS) &&
                (name.equals("state") || name.startsWith("cached-"));
    }

    private static boolean isOldLayoutFile(String name, Set<String> oldBundleNames) {
        return OLD_TOR_RUNTIME_NAMES.contains(name) ||
                name.startsWith(OLD_TOR_RUNTIME_PREFIX) ||
                name.equals(OLD_INSTALLATION_VERSION_FILE_NAME) ||
                oldBundleNames.contains(name);
    }

    // The entries of the new layout in the Tor directory, and the directory of the migration. The data directory is the
    // result of the migration: an entry at its path is no part of the layout yet.
    private static Set<String> newLayoutNames(TorDirectories directories) {
        Stream<String> layoutNames = directories.getLayoutEntries().stream()
                .filter(entry -> !entry.equals(directories.getDataDirPath()))
                .map(entry -> entry.getFileName().toString());
        return Stream.concat(layoutNames, Stream.of(MIGRATION_DIR_NAME)).collect(Collectors.toUnmodifiableSet());
    }

    // Losing the guards is better than failing every start, for example when an orphaned Tor locks a file on Windows.
    private static void moveTorState(Path source, Path target) {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            log.warn("Could not move {} into the Tor data directory", source.toAbsolutePath(), e);
        }
    }

    private static void deleteQuietly(Path entry) {
        try {
            FileUtils.deleteRecursively(entry);
        } catch (IOException e) {
            log.warn("Could not delete {} of the previous Tor directory layout", entry.toAbsolutePath(), e);
        }
    }
}
