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

import static org.assertj.core.api.Assertions.assertThat;

import com.irurueta.authserver.testsupport.PostgresTestConfiguration;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Playwright;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
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

    private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(2);

    private static final Pattern PASSWORD_LOG = Pattern.compile("demo user 'demo' with generated password: (\\S+)");

    private static final Pattern SECRET_LOG = Pattern.compile("client 'bff' with generated secret: (\\S+)");

    /**
     * Cookies are shared between ports of the same host, so the BFF is reached through a different host name than
     * the authorization server (which is {@code localhost}) to keep their {@code JSESSIONID} cookies apart.
     */
    private static final String BFF_HOST = "127.0.0.1";

    private static PostgreSQLContainer postgres;

    private static ManagedApp authServer;

    private static ManagedApp bff;

    private static int authPort;

    private static int bffPort;

    private static String demoPassword;

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
        assertThat(update.getExitCode()).as(update.getStderr()).isZero();

        bff = ManagedApp.start(bffJar, List.of("--server.port=" + bffPort),
                List.of("AUTH_ISSUER=" + issuer, "BFF_CLIENT_SECRET=" + clientSecret));
        bff.await(Pattern.compile("Started BffApplication in"), STARTUP_TIMEOUT);
    }

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

    @Test
    void demoUserSignsInThroughBff_bffUserContainsSubject() {
        try (var playwright = Playwright.create(); var browser = launch(playwright)) {
            final var page = browser.newPage();
            page.navigate("http://" + BFF_HOST + ":" + bffPort + "/oauth2/authorization/bff");

            page.waitForURL(url -> url.startsWith("http://localhost:" + authPort + "/login"));
            page.fill("#username", "demo");
            page.fill("#password", demoPassword);
            page.click("button[type=submit]");
            page.waitForURL(url -> url.startsWith("http://" + BFF_HOST + ":" + bffPort));

            final var response = page.navigate("http://" + BFF_HOST + ":" + bffPort + "/bff/user");
            assertThat(response.status()).isEqualTo(200);
            assertThat(response.text()).contains("\"subject\":\"demo\"");
        }
    }

    private static Browser launch(final Playwright playwright) {
        return playwright.chromium().launch();
    }

    private static Path jar(final String property) {
        final var value = System.getProperty(property);
        assertThat(value).as("system property " + property + " (set by Failsafe)").isNotBlank();
        final var path = Path.of(value).normalize();
        assertThat(path).as("packaged application, run './mvnw verify' from the repository root").exists();
        return path;
    }

    private static int freePort() throws IOException {
        try (var socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /** A Spring Boot application launched from its packaged jar, with its output captured. */
    private static final class ManagedApp {

        private final Process process;

        private final List<String> output = new ArrayList<>();

        private ManagedApp(final Process process) {
            this.process = process;
        }

        static ManagedApp start(final Path jar, final List<String> args, final List<String> environment)
                throws IOException {
            final var command = new ArrayList<String>();
            command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
            command.add("-jar");
            command.add(jar.toString());
            command.addAll(args);
            final var builder = new ProcessBuilder(command).redirectErrorStream(true);
            for (final var entry : environment) {
                final var idx = entry.indexOf('=');
                builder.environment().put(entry.substring(0, idx), entry.substring(idx + 1));
            }
            final var app = new ManagedApp(builder.start());
            final var reader = new Thread(app::pump, "e2e-output-" + jar.getFileName());
            reader.setDaemon(true);
            reader.start();
            return app;
        }

        private void pump() {
            try (var lines = new java.io.BufferedReader(new java.io.InputStreamReader(
                    process.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                String line;
                while ((line = lines.readLine()) != null) {
                    synchronized (output) {
                        output.add(line);
                        output.notifyAll();
                    }
                }
            } catch (final IOException ignored) {
                // process ended
            }
        }

        /** Waits until a log line matches and returns its first group (or the whole match). */
        String await(final Pattern pattern, final Duration timeout) throws InterruptedException {
            final var deadline = System.nanoTime() + timeout.toNanos();
            int seen = 0;
            synchronized (output) {
                while (true) {
                    while (seen < output.size()) {
                        final var matcher = pattern.matcher(output.get(seen++));
                        if (matcher.find()) {
                            return matcher.groupCount() > 0 ? matcher.group(1) : matcher.group();
                        }
                    }
                    final var remaining = deadline - System.nanoTime();
                    if (remaining <= 0 || !process.isAlive() && seen >= output.size()) {
                        throw new IllegalStateException("Application did not log " + pattern + ". Output tail:\n"
                                + String.join("\n", output.subList(Math.max(0, output.size() - 40), output.size())));
                    }
                    output.wait(Math.min(remaining / 1_000_000, 500));
                }
            }
        }

        void stop() {
            process.destroy();
            try {
                if (!process.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
            }
        }
    }
}
