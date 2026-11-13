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
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class TorDirectoryMigrationTest {
    // The top-level names of the bundle of macOS
    private static final Set<String> BUNDLE_NAMES = Set.of("tor", "libevent-2.1.7.dylib", "geoip", "geoip6",
            "torrc-defaults", "pluggable_transports");
    private static final String NETLAYER_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "dGhlIHNlY3JldCBzY2FsYXIgb2YgYW4gb25pb24gc2VydmljZSBrZXkgb2YgNjQgYnl0ZXM=\n" +
            "-----END OPENSSH PRIVATE KEY-----";

    @TempDir
    Path tempDirPath;

    @Test
    void movesTheStateOfTorAndDeletesTheOldBundle() throws IOException {
        Path base = tempDirPath.resolve("tor");
        // The layout before the sandbox: Tor data, bundled Tor and Bisq files in one directory.
        write(base.resolve("external_tor.config"), "UseExternalTor 1");
        write(base.resolve("state"), "Guard in EntryGuard");
        write(base.resolve("cached-microdesc-consensus"), "consensus");
        write(base.resolve("torrc"), "DataDirectory " + base);
        write(base.resolve("tor"), "binary");
        write(base.resolve("libevent-2.1.7.dylib"), "library");
        write(base.resolve("version"), "15.0.25-bundle-2");
        write(base.resolve("lock"), "");
        write(base.resolve("debug.log"), "log");
        write(base.resolve("unverified-microdesc-consensus"), "consensus");
        write(base.resolve("control").resolve("control"), "PORT=127.0.0.1:9051");
        write(base.resolve("pluggable_transports").resolve("lyrebird"), "binary");
        TorDirectories directories = new TorDirectories(base);

        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);

        assertThat(namesIn(base)).containsExactlyInAnyOrder("external_tor.config", "torrc", "data");
        assertThat(read(base.resolve("external_tor.config"))).isEqualTo("UseExternalTor 1");
        assertThat(namesIn(directories.getDataDirPath())).containsExactlyInAnyOrder("state", "cached-microdesc-consensus");
        assertThat(read(directories.getDataDirPath().resolve("state"))).isEqualTo("Guard in EntryGuard");
    }

    /**
     * A Tor directory of Bisq 1 which netlayer used before: the onion service key of the node, its backups, files of
     * netlayer which no current version installs, and a file of the user stay as they are.
     */
    @Test
    void keepsTheOnionServiceKeyOfBisq1AndEverythingItDoesNotKnow() throws IOException {
        Path base = tempDirPath.resolve("tor");
        Path hiddenservice = base.resolve("hiddenservice");
        write(hiddenservice.resolve("private_key"), NETLAYER_KEY);
        write(hiddenservice.resolve("hostname"), "ygce4jroabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop.onion");
        write(hiddenservice.resolve("backup").resolve("backups_private_key").resolve("private_key_1"), NETLAYER_KEY);
        write(base.resolve("tor.real"), "binary of netlayer up to Bisq 1.9.22");
        write(base.resolve("PluggableTransports").resolve("obfs4proxy"), "binary of netlayer");
        write(base.resolve("my-torrc"), "file of the user");
        write(base.resolve("state"), "Guard in EntryGuard");
        write(base.resolve("cached-certs"), "certs");
        write(base.resolve(".tor").resolve("control_auth_cookie"), "cookie");
        write(base.resolve("pid"), "4242");
        write(base.resolve("tor"), "binary of netlayer");
        write(base.resolve("geoip"), "geoip");
        TorDirectories directories = new TorDirectories(base);

        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);

        assertThat(namesIn(base)).containsExactlyInAnyOrder("hiddenservice", "tor.real", "PluggableTransports",
                "my-torrc", "data");
        assertThat(read(hiddenservice.resolve("private_key"))).isEqualTo(NETLAYER_KEY);
        assertThat(read(hiddenservice.resolve("hostname"))).startsWith("ygce4jro");
        assertThat(read(hiddenservice.resolve("backup").resolve("backups_private_key").resolve("private_key_1")))
                .isEqualTo(NETLAYER_KEY);
        assertThat(read(base.resolve("my-torrc"))).isEqualTo("file of the user");
        assertThat(namesIn(directories.getDataDirPath())).containsExactlyInAnyOrder("state", "cached-certs");
    }

    @Test
    void createsTheDataDirectoryOfANewInstallation() throws IOException {
        TorDirectories directories = new TorDirectories(tempDirPath.resolve("tor"));

        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);

        assertThat(namesIn(directories.getBaseDirPath())).containsExactly("data");
    }

    // The names come from the Tor bundle of the jar, which the reader inflates in full: not at every start.
    @Test
    void readsTheNamesOfTheBundleOnlyForAMigration() throws IOException {
        TorDirectories directories = new TorDirectories(tempDirPath.resolve("tor"));
        AtomicInteger reads = new AtomicInteger();
        TorDirectoryMigration.BundleNamesReader reader = () -> {
            reads.incrementAndGet();
            return BUNDLE_NAMES;
        };

        TorDirectoryMigration.migrateIfNeeded(directories, reader);
        TorDirectoryMigration.migrateIfNeeded(directories, reader);

        assertThat(reads).hasValue(1);
    }

    @Test
    void doesNothingAfterTheMigration() throws IOException {
        TorDirectories directories = new TorDirectories(tempDirPath.resolve("tor"));
        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);
        write(directories.getDataDirPath().resolve("state"), "state");
        write(directories.getTorrcPath(), "torrc");
        write(directories.getBinaryDirPath().resolve("tor"), "binary");

        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);

        assertThat(namesIn(directories.getBaseDirPath())).containsExactlyInAnyOrder("data", "torrc", "bin");
        assertThat(namesIn(directories.getDataDirPath())).containsExactly("state");
    }

    // Bisq 1 deletes the Tor files except the onion service key after a failed bootstrap.
    @Test
    void runsAgainAfterTheApplicationDeletedTheDataDirectory() throws IOException {
        Path base = tempDirPath.resolve("tor");
        write(base.resolve("hiddenservice").resolve("private_key"), NETLAYER_KEY);
        TorDirectories directories = new TorDirectories(base);
        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);
        Files.delete(directories.getDataDirPath());

        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);

        assertThat(namesIn(base)).containsExactlyInAnyOrder("hiddenservice", "data");
        assertThat(read(base.resolve("hiddenservice").resolve("private_key"))).isEqualTo(NETLAYER_KEY);
    }

    @Test
    void finishesAnInterruptedMigration() throws IOException {
        Path base = tempDirPath.resolve("tor");
        write(base.resolve(TorDirectoryMigration.MIGRATION_DIR_NAME).resolve("state"), "moved state");
        write(base.resolve("cached-certs"), "certs");
        write(base.resolve("tor"), "binary");
        TorDirectories directories = new TorDirectories(base);

        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);

        assertThat(namesIn(base)).containsExactly("data");
        assertThat(namesIn(directories.getDataDirPath())).containsExactlyInAnyOrder("state", "cached-certs");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void followsNoLinks() throws IOException {
        Path base = tempDirPath.resolve("tor");
        Path outside = tempDirPath.resolve("outside");
        write(outside.resolve("state"), "file outside");
        Files.createDirectories(base);
        Files.createSymbolicLink(base.resolve("state"), outside.resolve("state"));
        Files.createSymbolicLink(base.resolve("control"), outside);
        Files.createSymbolicLink(base.resolve("data"), outside);
        TorDirectories directories = new TorDirectories(base);

        TorDirectoryMigration.migrateIfNeeded(directories, BUNDLE_NAMES);

        // The link named state is unknown and stays; the links at known names are deleted, not their targets.
        assertThat(namesIn(base)).containsExactlyInAnyOrder("state", "data");
        assertThat(Files.isSymbolicLink(directories.getDataDirPath())).isFalse();
        assertThat(namesIn(outside)).containsExactly("state");
        assertThat(read(outside.resolve("state"))).isEqualTo("file outside");
    }

    // Installations which already have the layout of the sandbox get no migration, so the logs of versions up to 1.0.1
    // are removed at every start.
    @Test
    void removesTheLogsOfEarlierVersionsAtEveryStart() throws IOException {
        Path base = tempDirPath.resolve("tor");
        TorDirectories directories = new TorDirectories(base);
        write(base.resolve("tor-stdout.log"), "log of 1.0.1");
        write(base.resolve("tor-stdout.log.1"), "earlier log of 1.0.1");
        write(base.resolve("tor-stderr.log"), "sandy: run failed");
        write(directories.getLogPath(), "log");
        Files.createDirectories(directories.getDataDirPath());

        TorDirectoryMigration.removeObsoleteEntries(directories);
        TorDirectoryMigration.removeObsoleteEntries(directories);

        assertThat(namesIn(base)).containsExactlyInAnyOrder("tor.log", "data");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void removesALinkAtAnObsoletePathButNotItsTargetAndKeepsADirectory() throws IOException {
        Path base = tempDirPath.resolve("tor");
        Path outside = tempDirPath.resolve("outside");
        write(outside.resolve("file"), "file outside");
        Files.createDirectories(base.resolve("tor-stderr.log"));
        Files.createSymbolicLink(base.resolve("tor-stdout.log"), outside.resolve("file"));

        TorDirectoryMigration.removeObsoleteEntries(new TorDirectories(base));

        assertThat(namesIn(base)).containsExactly("tor-stderr.log");
        assertThat(read(outside.resolve("file"))).isEqualTo("file outside");
    }

    private static void write(Path path, String content) throws IOException {
        Files.createDirectories(path.getParent());
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));
    }

    private static String read(Path path) throws IOException {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    private static String[] namesIn(Path dirPath) throws IOException {
        try (Stream<Path> stream = Files.list(dirPath)) {
            return stream.map(path -> path.getFileName().toString()).toArray(String[]::new);
        }
    }
}
