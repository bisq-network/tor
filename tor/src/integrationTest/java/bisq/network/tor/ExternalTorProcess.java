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

import bisq.network.tor.common.torrc.DirectoryAuthority;
import bisq.network.tor.controller.PasswordDigest;
import bisq.network.tor.controller.TorControlProtocol;
import bisq.network.tor.process.EmbeddedTorProcess;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * A Tor which Bisq does not start, as a user runs one: a client of a private Tor network whose control port takes the
 * cookie or the password of the Tor. Bisq uses it through external_tor.config.
 */
final class ExternalTorProcess implements AutoCloseable {
    private static final long CONTROL_PORT_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(30);
    private static final String CONTROL_PASSWORD = "integration-test-password";

    // How Bisq authenticates on the control port, the two ways which external_tor.config offers
    enum Authentication {
        COOKIE,
        PASSWORD
    }

    private final Process process;
    private final int controlPort;
    private final Authentication authentication;
    private final Path cookieAuthFilePath;

    private ExternalTorProcess(Process process, int controlPort, Authentication authentication,
                               Path cookieAuthFilePath) {
        this.process = process;
        this.controlPort = controlPort;
        this.authentication = authentication;
        this.cookieAuthFilePath = cookieAuthFilePath;
    }

    static ExternalTorProcess start(Path torDirPath,
                                    Set<DirectoryAuthority> directoryAuthorities,
                                    Authentication authentication) throws IOException, InterruptedException {
        Path dataDirPath = Files.createDirectories(torDirPath.resolve("data"));
        Path controlPortFilePath = torDirPath.resolve("control-port");
        Path cookieAuthFilePath = torDirPath.resolve("control_auth_cookie");
        List<String> torrcLines = new ArrayList<>(List.of(
                "DataDirectory " + dataDirPath,
                "TestingTorNetwork 1",
                "SocksPort 127.0.0.1:auto",
                "ControlPort 127.0.0.1:auto",
                "ControlPortWriteToFile " + controlPortFilePath,
                "Log notice file " + torDirPath.resolve("tor.log")));
        if (authentication == Authentication.COOKIE) {
            torrcLines.add("CookieAuthentication 1");
            torrcLines.add("CookieAuthFile " + cookieAuthFilePath);
        } else {
            PasswordDigest passwordDigest = new PasswordDigest(CONTROL_PASSWORD.getBytes(StandardCharsets.UTF_8));
            torrcLines.add("HashedControlPassword " + passwordDigest.getHashedPassword());
        }
        directoryAuthorities.forEach(authority -> torrcLines.add("DirAuthority " + authority.toTorrcValue()));
        Path torrcPath = Files.write(torDirPath.resolve("torrc"), torrcLines);

        // A user runs the tor of the system
        Path torBinaryPath = EmbeddedTorProcess.findExecutableInPath(System.getenv("PATH"), "tor")
                .orElseThrow(() -> new IllegalStateException("No tor in PATH"));
        // Tor ends with this JVM, also if the test does not stop it
        String ownerPid = String.valueOf(ProcessHandle.current().pid());
        Process process = new ProcessBuilder(EmbeddedTorProcess.torCommand(torBinaryPath, torrcPath, ownerPid))
                .redirectErrorStream(true)
                .redirectOutput(torDirPath.resolve("tor.log").toFile())
                .start();
        try {
            return new ExternalTorProcess(process, readControlPort(controlPortFilePath, process), authentication,
                    cookieAuthFilePath);
        } catch (IOException | InterruptedException | RuntimeException e) {
            process.destroyForcibly();
            throw e;
        }
    }

    // Tor writes PORT=127.0.0.1:<port> once it listens on its control port
    private static int readControlPort(Path controlPortFilePath, Process process) throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + CONTROL_PORT_TIMEOUT_MS;
        while (!Files.exists(controlPortFilePath) || Files.readString(controlPortFilePath).isBlank()) {
            if (!process.isAlive()) {
                throw new IOException("The external Tor exited with " + process.exitValue());
            }
            if (System.currentTimeMillis() > deadline) {
                throw new IOException("The external Tor did not open its control port");
            }
            Thread.sleep(100);
        }
        String controlPortLine = Files.readString(controlPortFilePath, StandardCharsets.US_ASCII).trim();
        return Integer.parseInt(controlPortLine.substring(controlPortLine.lastIndexOf(':') + 1));
    }

    /**
     * A control connection of the test itself, authenticated with the password. Only for {@link Authentication#PASSWORD}.
     */
    TorControlProtocol connectController() {
        TorControlProtocol torControlProtocol = new TorControlProtocol();
        torControlProtocol.initialize(controlPort);
        torControlProtocol.authenticateWithPassword(CONTROL_PASSWORD);
        return torControlProtocol;
    }

    String toExternalTorConfig() {
        String authenticationConfig = authentication == Authentication.COOKIE ?
                "CookieAuthentication 1\nCookieAuthFile " + cookieAuthFilePath + "\n" :
                "ControlPassword " + CONTROL_PASSWORD + "\n";
        return "UseExternalTor 1\n" +
                authenticationConfig +
                "ControlPort 127.0.0.1:" + controlPort + "\n";
    }

    @Override
    public void close() throws InterruptedException {
        process.destroy();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
        }
    }
}
