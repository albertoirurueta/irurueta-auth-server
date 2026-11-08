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
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * The packaged {@code auth-server} running in the {@code dev} profile (so the demo user and the {@code bff} client
 * are seeded with generated secrets) against a PostgreSQL container, shared by the end-to-end tests. Everything
 * secret is generated per run: the key-encryption passphrase and salt handed to the application, and the
 * credentials the application logs.
 */
final class RunningAuthServer implements AutoCloseable {

    /** Longest wait for an application to log a given startup line. */
    static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(2);

    /** Pause between two checks for the first signing key, in milliseconds. */
    private static final long SIGNING_KEY_POLL_MILLIS = 100L;

    /** Number of random bytes of the generated key-encryption salt. */
    private static final int SALT_BYTES = 16;

    /** Matches the log line carrying the generated demo user password. */
    private static final Pattern PASSWORD_LOG = Pattern.compile("demo user 'demo' with generated password: (\\S+)");

    /** Matches the log line carrying the generated {@code bff} client secret. */
    private static final Pattern SECRET_LOG = Pattern.compile("client 'bff' with generated secret: (\\S+)");

    /** The database of the server. */
    private final PostgreSQLContainer postgres;

    /** The packaged server. */
    private final ManagedApp app;

    /** Port of the server. */
    private final int port;

    /** Generated password of the demo user. */
    private final String demoPassword;

    /** Generated secret of the {@code bff} client. */
    private final String clientSecret;

    /**
     * Wraps a started server.
     *
     * @param postgres     the database.
     * @param app          the server process.
     * @param port         port of the server.
     * @param demoPassword generated password of the demo user.
     * @param clientSecret generated secret of the {@code bff} client.
     */
    private RunningAuthServer(final PostgreSQLContainer postgres, final ManagedApp app, final int port,
                              final String demoPassword, final String clientSecret) {
        this.postgres = postgres;
        this.app = app;
        this.port = port;
        this.demoPassword = demoPassword;
        this.clientSecret = clientSecret;
    }

    /**
     * Starts the database and the server, and waits until the seeded credentials are logged.
     *
     * @return the running server.
     * @throws Exception if the container or the server cannot be started.
     */
    static RunningAuthServer start() throws Exception {
        return start(List.of());
    }

    /**
     * Starts the database and the server with extra command-line arguments (for example the redirect URIs of the
     * seeded clients), and waits until the seeded credentials are logged.
     *
     * The relying party of the passkeys is {@code localhost} (the default) and its allowed origin is the random port
     * of the server, as browsers only run a WebAuthn ceremony from an origin the server lists.
     *
     * @param extraArguments arguments added after the default ones, so they win over them.
     * @return the running server.
     * @throws Exception if the container or the server cannot be started.
     */
    static RunningAuthServer start(final List<String> extraArguments) throws Exception {
        final var port = freePort();
        final var postgres = new PostgreSQLContainer(DockerImageName.parse(PostgresTestConfiguration.POSTGRES_IMAGE));
        postgres.start();
        final var salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        final var arguments = new ArrayList<>(List.of(
                "--spring.profiles.active=dev",
                "--spring.docker.compose.enabled=false",
                "--server.port=" + port,
                "--authserver.passkeys.allowed-origins=http://localhost:" + port,
                "--spring.datasource.url=" + postgres.getJdbcUrl(),
                "--spring.datasource.username=" + postgres.getUsername(),
                "--spring.datasource.password=" + postgres.getPassword()));
        arguments.addAll(extraArguments);
        final var app = ManagedApp.start(jar("authserver.jar"), arguments,
                List.of("AUTHSERVER_ISSUER_URL=http://localhost:" + port,
                        "AUTHSERVER_KEYS_ENCRYPTION_PASSWORD=" + UUID.randomUUID(),
                        "AUTHSERVER_KEYS_ENCRYPTION_SALT=" + HexFormat.of().formatHex(salt)));
        final var demoPassword = app.await(PASSWORD_LOG, STARTUP_TIMEOUT);
        final var clientSecret = app.await(SECRET_LOG, STARTUP_TIMEOUT);
        final var server = new RunningAuthServer(postgres, app, port, demoPassword, clientSecret);
        server.awaitSigningKey();
        return server;
    }

    /**
     * Resolves a packaged application jar from a system property set by Failsafe.
     *
     * @param property the system property naming the jar.
     * @return the jar's path.
     */
    static Path jar(final String property) {
        final var value = System.getProperty(property);
        assertFalse(value == null || value.isBlank(), "system property " + property + " (set by Failsafe)");
        final var path = Path.of(value).normalize();
        assertTrue(Files.exists(path),
                "packaged application " + path + ", run './mvnw verify' from the repository root");
        return path;
    }

    /**
     * Waits until the server has stored its first signing key. The bootstrap runner that creates it runs after the
     * seeded credentials are logged, so a test that asks for a token right away (without a browser sign-in first)
     * would otherwise race it and get a 500 ("Failed to select a JWK signing key").
     *
     * @throws Exception if the database cannot be queried.
     */
    private void awaitSigningKey() throws Exception {
        final var deadline = System.nanoTime() + STARTUP_TIMEOUT.toNanos();
        while (System.nanoTime() < deadline) {
            if (!"0".equals(query("SELECT count(*) FROM signing_keys").getFirst())) {
                return;
            }
            Thread.sleep(SIGNING_KEY_POLL_MILLIS);
        }
        throw new IllegalStateException("The server did not store a signing key within " + STARTUP_TIMEOUT);
    }

    /**
     * Finds a free local TCP port.
     *
     * @return a port that was free a moment ago.
     * @throws IOException if no socket can be opened.
     */
    static int freePort() throws IOException {
        try (var socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /**
     * Returns the port of the server.
     *
     * @return the port.
     */
    int port() {
        return port;
    }

    /**
     * Returns the issuer URL of the server.
     *
     * @return the issuer.
     */
    String issuer() {
        return "http://localhost:" + port;
    }

    /**
     * Returns the generated password of the demo user.
     *
     * @return the password.
     */
    String demoPassword() {
        return demoPassword;
    }

    /**
     * Returns the generated secret of the {@code bff} client.
     *
     * @return the secret.
     */
    String clientSecret() {
        return clientSecret;
    }

    /**
     * Runs a SQL statement against the server's database.
     *
     * @param statement the statement.
     * @throws Exception if the statement cannot be run.
     */
    void sql(final String statement) throws Exception {
        final var result = postgres.execInContainer("psql", "-U", postgres.getUsername(), "-d",
                postgres.getDatabaseName(), "-v", "ON_ERROR_STOP=1", "-c", statement);
        assertEquals(0, result.getExitCode(), result.getStderr());
    }

    /**
     * Creates a user that is a copy of the seeded {@code demo} user (same password, authorities, tenant) under another
     * name, so that a test can change the state of its user (register passkeys, for example) without affecting the
     * tests that share the server.
     *
     * @param username name of the new user; it is also its e-mail local part.
     * @throws Exception if the statement cannot be run.
     */
    void createUserLikeDemo(final String username) throws Exception {
        sql("WITH src AS (SELECT id, tenant FROM users WHERE username = 'demo'), "
                + "created AS (INSERT INTO users (id, username, email, email_verified, tenant) "
                + "SELECT gen_random_uuid(), '" + username + "', '" + username + "@example.com', TRUE, tenant "
                + "FROM src RETURNING id), "
                + "granted AS (INSERT INTO user_authorities (user_id, authority) "
                + "SELECT created.id, ua.authority FROM created, src, user_authorities ua WHERE ua.user_id = src.id "
                + "RETURNING 1) "
                + "INSERT INTO user_passwords (user_id, encoded_password) "
                + "SELECT created.id, up.encoded_password FROM created, src, user_passwords up "
                + "WHERE up.user_id = src.id");
    }

    /**
     * Runs a SQL query against one of the databases of the container and returns the first column of every row.
     *
     * @param database name of the database.
     * @param query    the query.
     * @return the values of the first column, one per row (an empty list when there are no rows).
     * @throws Exception if the query cannot be run.
     */
    List<String> query(final String database, final String query) throws Exception {
        final var result = postgres.execInContainer("psql", "-U", postgres.getUsername(), "-d", database,
                "-v", "ON_ERROR_STOP=1", "-t", "-A", "-c", query);
        assertEquals(0, result.getExitCode(), result.getStderr());
        return result.getStdout().lines().filter(line -> !line.isBlank()).toList();
    }

    /**
     * Runs a SQL query against the database of the authorization server.
     *
     * @param query the query.
     * @return the values of the first column, one per row.
     * @throws Exception if the query cannot be run.
     */
    List<String> query(final String query) throws Exception {
        return query(postgres.getDatabaseName(), query);
    }

    /**
     * Creates the {@code bff} database in the server's PostgreSQL container, the way the compose init script does,
     * and returns the command-line arguments that point a packaged BFF at it.
     *
     * @return the datasource arguments of the BFF.
     * @throws Exception if the database cannot be created.
     */
    List<String> bffDatabaseArguments() throws Exception {
        final var result = postgres.execInContainer("psql", "-U", postgres.getUsername(), "-d",
                postgres.getDatabaseName(), "-v", "ON_ERROR_STOP=1", "-c", "CREATE DATABASE bff");
        assertEquals(0, result.getExitCode(), result.getStderr());
        return List.of(
                "--spring.datasource.url=" + postgres.getJdbcUrl().replace("/" + postgres.getDatabaseName(), "/bff"),
                "--spring.datasource.username=" + postgres.getUsername(),
                "--spring.datasource.password=" + postgres.getPassword());
    }

    /** Stops the server and the database. */
    @Override
    public void close() {
        app.stop();
        postgres.stop();
    }
}
