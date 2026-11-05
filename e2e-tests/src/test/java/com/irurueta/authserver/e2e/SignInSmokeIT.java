/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.irurueta.authserver.e2e;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.testsupport.PostgresTestConfiguration;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Playwright;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Smoke test of the whole sign-in flow: the packaged {@code auth-server} (dev profile, so the demo user and the
 * {@code bff} client are seeded with generated secrets) and {@code bff} are started on random ports against a
 * PostgreSQL container, and the demo user signs in through the BFF in headless Chromium.
 */
class SignInSmokeIT {

    /**
     * Longest wait for an application to log a given startup line.
     */
    private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(2);

    /**
     * Matches the log line carrying the generated demo user password.
     */
    private static final Pattern PASSWORD_LOG = Pattern.compile("demo user 'demo' with generated password: (\\S+)");

    /**
     * Matches the log line carrying the generated {@code bff} client secret.
     */
    private static final Pattern SECRET_LOG = Pattern.compile("client 'bff' with generated secret: (\\S+)");

    /**
     * Matches the log line printed once the BFF is up.
     */
    private static final Pattern BFF_STARTED = Pattern.compile("Started BffApplication in");

    /**
     * Cookies are shared between ports of the same host, so the BFF is reached through a different host name than
     * the authorization server (which is {@code localhost}) to keep their {@code JSESSIONID} cookies apart.
     */
    private static final String BFF_HOST = "127.0.0.1";

    /**
     * HTTP status of a successful response.
     */
    private static final int HTTP_OK = 200;

    /**
     * PostgreSQL container shared by the authorization server.
     */
    private static PostgreSQLContainer postgres;

    /**
     * The packaged authorization server.
     */
    private static ManagedApp authServer;

    /**
     * The packaged backend-for-frontend.
     */
    private static ManagedApp bff;

    /**
     * Port of the authorization server.
     */
    private static int authPort;

    /**
     * Port of the BFF.
     */
    private static int bffPort;

    /**
     * Generated password of the demo user.
     */
    private static String demoPassword;

    /**
     * Starts the database and both applications, and points the seeded {@code bff} client at the BFF's port.
     *
     * @throws Exception if an application or the container cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        final var authJar = jar("authserver.jar");
        final var bffJar = jar("bff.jar");
        authPort = freePort();
        bffPort = freePort();
        final var issuer = "http://localhost:" + authPort;

        postgres = new PostgreSQLContainer(DockerImageName.parse(PostgresTestConfiguration.POSTGRES_IMAGE));
        postgres.start();

        authServer = ManagedApp.start(authJar, List.of(
                "--spring.profiles.active=dev",
                "--spring.docker.compose.enabled=false",
                "--server.port=" + authPort,
                "--spring.datasource.url=" + postgres.getJdbcUrl(),
                "--spring.datasource.username=" + postgres.getUsername(),
                "--spring.datasource.password=" + postgres.getPassword()),
                List.of("AUTHSERVER_ISSUER_URL=" + issuer));
        demoPassword = authServer.await(PASSWORD_LOG, STARTUP_TIMEOUT);
        final var clientSecret = authServer.await(SECRET_LOG, STARTUP_TIMEOUT);

        // the dev client is registered for http://localhost:8080; point it at the random BFF port instead
        final var redirect = "http://" + BFF_HOST + ":" + bffPort + "/login/oauth2/code/bff";
        final var update = postgres.execInContainer("psql", "-U", postgres.getUsername(), "-d",
                postgres.getDatabaseName(), "-c",
                "UPDATE oauth2_registered_client SET redirect_uris = '" + redirect + "' WHERE client_id = 'bff'");
        assertEquals(0, update.getExitCode(), update.getStderr());

        bff = ManagedApp.start(bffJar, List.of("--server.port=" + bffPort),
                List.of("AUTH_ISSUER=" + issuer, "BFF_CLIENT_SECRET=" + clientSecret));
        bff.await(BFF_STARTED, STARTUP_TIMEOUT);
    }

    /**
     * Stops both applications and the database.
     */
    @AfterAll
    static void stopApplications() {
        if (bff != null) {
            bff.stop();
        }
        if (authServer != null) {
            authServer.stop();
        }
        if (postgres != null) {
            postgres.stop();
        }
    }

    /**
     * Signs the demo user in through the BFF and reads the BFF's user endpoint.
     */
    @Test
    void bffUser_whenDemoUserSignsIn_containsSubject() {
        try (var playwright = Playwright.create(); var browser = launch(playwright)) {
            final var page = browser.newPage();
            page.navigate("http://" + BFF_HOST + ":" + bffPort + "/oauth2/authorization/bff");

            page.waitForURL(url -> url.startsWith("http://localhost:" + authPort + "/login"));
            page.fill("#username", "demo");
            page.fill("#password", demoPassword);
            page.click("button[type=submit]");
            page.waitForURL(url -> url.startsWith("http://" + BFF_HOST + ":" + bffPort));

            final var response = page.navigate("http://" + BFF_HOST + ":" + bffPort + "/bff/user");
            assertEquals(HTTP_OK, response.status());
            assertTrue(response.text().contains("\"subject\":\"demo\""));
        }
    }

    /**
     * Launches headless Chromium.
     *
     * @param playwright the Playwright instance.
     * @return the browser.
     */
    private static Browser launch(final Playwright playwright) {
        return playwright.chromium().launch();
    }

    /**
     * Resolves a packaged application jar from a system property set by Failsafe.
     *
     * @param property the system property naming the jar.
     * @return the jar's path.
     */
    private static Path jar(final String property) {
        final var value = System.getProperty(property);
        assertFalse(value == null || value.isBlank(), "system property " + property + " (set by Failsafe)");
        final var path = Path.of(value).normalize();
        assertTrue(Files.exists(path),
                "packaged application " + path + ", run './mvnw verify' from the repository root");
        return path;
    }

    /**
     * Finds a free local TCP port.
     *
     * @return a port that was free a moment ago.
     * @throws IOException if no socket can be opened.
     */
    private static int freePort() throws IOException {
        try (var socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
