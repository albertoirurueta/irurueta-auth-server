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

import com.irurueta.authserver.testsupport.TestPki;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The packaged {@code resource-server} on a random port, validating the tokens of an authorization server, either
 * over plain HTTP or over TLS with a client certificate requested but not required ({@code client-auth: want}), the
 * way a resource server that accepts certificate-bound tokens is set up.
 */
final class RunningResourceServer implements AutoCloseable {

    /** Matches the log line printed once the resource server is up. */
    private static final Pattern STARTED = Pattern.compile("Started ResourceServerApplication in");

    /** Alias of the private key entry that {@link TestPki} gives every identity. */
    private static final String ENTITY_ALIAS = "entity";

    /** The server process. */
    private final ManagedApp app;

    /** Port of the server. */
    private final int port;

    /** Whether the server speaks TLS. */
    private final boolean tls;

    /**
     * Wraps a started server.
     *
     * @param app  the server process.
     * @param port port of the server.
     * @param tls  whether the server speaks TLS.
     */
    private RunningResourceServer(final ManagedApp app, final int port, final boolean tls) {
        this.app = app;
        this.port = port;
        this.tls = tls;
    }

    /**
     * Starts a resource server over plain HTTP.
     *
     * @param issuer issuer of the authorization server whose tokens it accepts.
     * @return the running server.
     * @throws Exception if the server cannot be started.
     */
    static RunningResourceServer start(final String issuer) throws Exception {
        return start(issuer, null, null);
    }

    /**
     * Starts a resource server over TLS, with its server certificate from a test infrastructure and a client
     * certificate requested (not required), trusting the authority that issued {@code server}.
     *
     * @param issuer issuer of the authorization server whose tokens it accepts.
     * @param server identity (key store with the server certificate and its authority) of the server.
     * @return the running server.
     * @throws Exception if the server cannot be started.
     */
    static RunningResourceServer startWithTls(final String issuer, final TestPki.Identity server) throws Exception {
        return start(issuer, server, "want");
    }

    /**
     * Starts a resource server.
     *
     * @param issuer     issuer of the authorization server whose tokens it accepts.
     * @param server     identity of the server, or {@code null} for plain HTTP.
     * @param clientAuth value of {@code server.ssl.client-auth}, ignored for plain HTTP.
     * @return the running server.
     * @throws Exception if the server cannot be started.
     */
    private static RunningResourceServer start(final String issuer, final TestPki.Identity server,
                                               final String clientAuth) throws Exception {
        final var port = RunningAuthServer.freePort();
        final var arguments = new ArrayList<String>();
        arguments.add("--server.port=" + port);
        if (server != null) {
            arguments.addAll(List.of(
                    "--server.ssl.key-store=" + server.keyStore(),
                    "--server.ssl.key-store-password=" + server.password(),
                    "--server.ssl.key-store-type=PKCS12",
                    "--server.ssl.key-alias=" + ENTITY_ALIAS,
                    "--server.ssl.trust-store=" + server.keyStore(),
                    "--server.ssl.trust-store-password=" + server.password(),
                    "--server.ssl.trust-store-type=PKCS12",
                    "--server.ssl.client-auth=" + clientAuth,
                    "--server.ssl.enabled-protocols=TLSv1.2"));
        }
        final var app = ManagedApp.start(RunningAuthServer.jar("resourceserver.jar"), arguments,
                List.of("AUTH_ISSUER=" + issuer));
        app.await(STARTED, RunningAuthServer.STARTUP_TIMEOUT);
        return new RunningResourceServer(app, port, server != null);
    }

    /**
     * Returns the base URI of the server, without a trailing slash.
     *
     * @return the base URI.
     */
    String baseUri() {
        return (tls ? "https" : "http") + "://localhost:" + port;
    }

    /**
     * Returns the URI of the documents endpoint.
     *
     * @return the URI.
     */
    URI documentsUri() {
        return URI.create(baseUri() + "/api/documents");
    }

    /**
     * Stops the server.
     *
     * @throws IOException never; declared so that the resource can be closed in a try block with other resources.
     */
    @Override
    public void close() throws IOException {
        app.stop();
    }
}
