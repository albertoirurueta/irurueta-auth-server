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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * End-to-end test of the token exchange (RFC 8693) with the packaged applications: the demo user signs in through the
 * authorization code flow with PKCE in headless Chromium and gets an access token; the {@code service-client} jar,
 * under its {@code token-exchange} profile, takes that token as the subject and its own client credentials token as
 * the actor,
 * gets a token for the resource server and lists the user's documents with it. The exchanged token is the user's
 * ({@code sub}) and names the service client as the party acting for the user ({@code act.sub}).
 */
class TokenExchangeEndToEndIT {

    /** Redirect URI of the seeded {@code bff} client; nothing listens there, the browser's request is intercepted. */
    private static final String BFF_REDIRECT_URI = "http://127.0.0.1:8099/callback";

    /** Grant type of the token exchange. */
    private static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

    /** Name of the demo user. */
    private static final String DEMO_USER = "demo";

    /** The packaged authorization server and its database. */
    private static RunningAuthServer authServer;

    /** The packaged resource server. */
    private static RunningResourceServer resourceServer;

    /** Identifier of the service client that exchanges. */
    private static String clientId;

    /** Generated secret of the service client. */
    private static String clientSecret;

    /**
     * Starts the applications and registers the service client, which may use the client credentials and token exchange
     * grants.
     *
     * @throws Exception if an application or the container cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        authServer = RunningAuthServer.start(List.of("--authserver.clients.bff.redirect-uris=" + BFF_REDIRECT_URI));
        resourceServer = RunningResourceServer.start(authServer.issuer());
        clientId = "e2e-exchange-" + UUID.randomUUID();
        clientSecret = new ClientAdminApi(authServer).create(ClientAdminApi.confidentialClient(clientId,
                List.of("client_secret_basic"), List.of("client_credentials", TOKEN_EXCHANGE_GRANT)));
    }

    /**
     * Stops the applications and the database.
     *
     * @throws Exception if the resource server cannot be closed.
     */
    @AfterAll
    static void stopApplications() throws Exception {
        if (resourceServer != null) {
            resourceServer.close();
        }
        if (authServer != null) {
            authServer.close();
        }
    }

    /**
     * Verifies that the tool reads the documents on behalf of the signed-in user and that the exchanged token is the
     * user's, with the service client as actor.
     *
     * @throws Exception if a step fails.
     */
    @Test
    void tokenExchange_whenTheUserSignedIn_theToolActsOnBehalfOfTheUser() throws Exception {
        final var userToken = UserTokenFlow.bffAccessToken(authServer, BFF_REDIRECT_URI, "openid documents.read");
        assertEquals(DEMO_USER, JwtClaims.of(userToken).get("sub").asString());

        final var run = run(userToken);

        assertEquals(0, run.exitCode(), run.describe());
        final var exchanged = JwtClaims.of(run.accessToken());
        assertNotEquals(userToken, run.accessToken(), "the tool printed the exchanged token, not the user's");
        assertEquals(DEMO_USER, exchanged.get("sub").asString());
        assertEquals(clientId, exchanged.get("act").get("sub").asString());
        assertTrue(exchanged.get("aud").toString().contains(ClientAdminApi.RESOURCE_SERVER_AUDIENCE),
                exchanged.toString());
        assertTrue(exchanged.get("scope").toString().contains(ClientAdminApi.DOCUMENTS_READ), exchanged.toString());
    }

    /**
     * Verifies that a subject token the server did not issue makes the tool fail and read nothing.
     *
     * @throws Exception if the tool cannot be run.
     */
    @Test
    void tokenExchange_whenTheSubjectTokenIsForeign_theToolFails() throws Exception {
        final var run = run("not-a-token-this-server-issued");

        assertNotEquals(0, run.exitCode(), run.describe());
        assertTrue(run.documents().isEmpty());
    }

    /**
     * Runs the tool with the profile {@code token-exchange}.
     *
     * @param subjectToken the access token of the user.
     * @return the run.
     * @throws Exception if the tool cannot be run.
     */
    private static ServiceClientRun run(final String subjectToken) throws Exception {
        final var env = new ArrayList<>(List.of(
                "SERVICE_CLIENT_ID=" + clientId,
                "SERVICE_CLIENT_SECRET=" + clientSecret,
                "SERVICE_CLIENT_TOKEN_URI=" + authServer.issuer() + "/oauth2/token",
                "SERVICE_CLIENT_RESOURCE_SERVER_URI=" + resourceServer.baseUri(),
                "SERVICE_CLIENT_PRINT_ACCESS_TOKEN=true",
                "SERVICE_CLIENT_SUBJECT_TOKEN=" + subjectToken));
        return ServiceClientRun.run("token-exchange", List.of(), env);
    }
}
