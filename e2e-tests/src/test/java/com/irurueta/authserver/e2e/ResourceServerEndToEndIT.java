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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Route;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * End-to-end test with a real token: the packaged {@code auth-server} and {@code resource-server} run on random
 * ports against a PostgreSQL container, the demo user signs in with the authorization code flow and PKCE in
 * headless Chromium (the redirect to the client is intercepted, no client application is needed), the code is
 * exchanged for an access token, and that token is presented to the resource server. A token issued for another
 * audience must be rejected. A second resource server runs the {@code opaque} profile and validates reference tokens
 * through the authorization server's introspection endpoint.
 */
class ResourceServerEndToEndIT {

    /**
     * Redirect URI of the test clients. Nothing listens there: the browser's request to it is intercepted.
     */
    private static final String REDIRECT_URI = "http://127.0.0.1:8099/callback";

    /**
     * Client that gets tokens for the audience the resource server accepts.
     */
    private static final String ACCEPTED_CLIENT = "bff";

    /**
     * Client that gets tokens for an audience the resource server does not accept.
     */
    private static final String OTHER_AUDIENCE_CLIENT = "bff-other-audience";

    /**
     * Client that gets reference (opaque) access tokens for the audience the resource server accepts.
     */
    private static final String REFERENCE_CLIENT = "bff-reference";

    /**
     * Matches the log line printed once the resource server is up.
     */
    private static final Pattern RESOURCE_SERVER_STARTED = Pattern.compile("Started ResourceServerApplication in");

    /**
     * Matches the access token in the token endpoint's answer.
     */
    private static final Pattern ACCESS_TOKEN = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");

    /**
     * Number of random bytes of a PKCE code verifier.
     */
    private static final int VERIFIER_BYTES = 32;

    /**
     * HTTP status of a successful response.
     */
    private static final int HTTP_OK = 200;

    /**
     * HTTP status of an unauthorized response.
     */
    private static final int HTTP_UNAUTHORIZED = 401;

    /**
     * The packaged authorization server and its database.
     */
    private static RunningAuthServer authServer;

    /**
     * The packaged resource server.
     */
    private static ManagedApp resourceServer;

    /**
     * Port of the resource server.
     */
    private static int resourcePort;

    /**
     * The packaged resource server in its {@code opaque} profile, validating tokens by introspection.
     */
    private static ManagedApp opaqueResourceServer;

    /**
     * Port of the opaque-token resource server.
     */
    private static int opaquePort;

    /**
     * Starts the authorization server, registers the test clients and starts the resource server.
     *
     * @throws Exception if an application or the container cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        resourcePort = RunningAuthServer.freePort();
        opaquePort = RunningAuthServer.freePort();
        // the seeded bff client may read documents as it is; only its redirect URI is the intercepted one
        authServer = RunningAuthServer.start(List.of("--authserver.clients.bff.redirect-uris=" + REDIRECT_URI));

        // a copy of the bff client for another audience shows that the resource server tells the audiences apart;
        // another copy gets reference tokens, for the resource server in its opaque profile
        copyClient(OTHER_AUDIENCE_CLIENT, "replace(client_settings, 'resource-server', 'another-api')",
                "token_settings");
        copyClient(REFERENCE_CLIENT, "client_settings", "replace(token_settings, 'self-contained', 'reference')");

        resourceServer = ManagedApp.start(RunningAuthServer.jar("resourceserver.jar"),
                List.of("--server.port=" + resourcePort), List.of("AUTH_ISSUER=" + authServer.issuer()));
        // the opaque variant introspects with the bff client's own credentials: any confidential client will do
        opaqueResourceServer = ManagedApp.start(RunningAuthServer.jar("resourceserver.jar"),
                List.of("--server.port=" + opaquePort, "--spring.profiles.active=opaque"),
                List.of("AUTH_ISSUER=" + authServer.issuer(),
                        "AUTH_INTROSPECTION_URI=" + authServer.issuer() + "/oauth2/introspect",
                        "INTROSPECTION_CLIENT_ID=" + ACCEPTED_CLIENT,
                        "INTROSPECTION_CLIENT_SECRET=" + authServer.clientSecret()));
        resourceServer.await(RESOURCE_SERVER_STARTED, RunningAuthServer.STARTUP_TIMEOUT);
        opaqueResourceServer.await(RESOURCE_SERVER_STARTED, RunningAuthServer.STARTUP_TIMEOUT);
    }

    /**
     * Stops both applications and the database.
     */
    @AfterAll
    static void stopApplications() {
        if (resourceServer != null) {
            resourceServer.stop();
        }
        if (opaqueResourceServer != null) {
            opaqueResourceServer.stop();
        }
        if (authServer != null) {
            authServer.close();
        }
    }

    /**
     * Verifies that a real access token issued for the resource server's audience is accepted.
     *
     * @throws Exception if a flow step fails.
     */
    @Test
    void documents_whenTokenIsRealAndForTheAudience_returnsOk() throws Exception {
        final var token = obtainAccessToken(ACCEPTED_CLIENT);

        assertEquals(HTTP_OK, listDocuments(token));
    }

    /**
     * Verifies that a real access token issued for another audience is rejected.
     *
     * @throws Exception if a flow step fails.
     */
    @Test
    void documents_whenTokenIsRealButForAnotherAudience_returnsUnauthorized() throws Exception {
        final var token = obtainAccessToken(OTHER_AUDIENCE_CLIENT);

        assertEquals(HTTP_UNAUTHORIZED, listDocuments(token));
    }

    /**
     * Verifies that the resource server in its {@code opaque} profile accepts a real reference token for its
     * audience: the authorization server introspects it with its audience and roles, and rejects a JWT for another
     * audience as well.
     *
     * @throws Exception if a flow step fails.
     */
    @Test
    void documents_whenOpaqueProfileGetsAReferenceTokenForTheAudience_returnsOk() throws Exception {
        final var token = obtainAccessToken(REFERENCE_CLIENT);

        assertFalse(token.contains("."), "a reference token is not a JWT");
        assertEquals(HTTP_OK, listDocuments(opaqueUri(), token));
        assertEquals(HTTP_UNAUTHORIZED, listDocuments(opaqueUri(), obtainAccessToken(OTHER_AUDIENCE_CLIENT)));
    }

    /**
     * Verifies that a request without a token is rejected.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void documents_whenThereIsNoToken_returnsUnauthorized() throws Exception {
        final var request = HttpRequest.newBuilder(documentsUri()).GET().build();

        assertEquals(HTTP_UNAUTHORIZED,
                HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode());
    }

    /**
     * Runs the authorization code flow with PKCE for the demo user and returns the access token.
     *
     * @param clientId client that requests the token.
     * @return the access token.
     * @throws Exception if a flow step fails.
     */
    private static String obtainAccessToken(final String clientId) throws Exception {
        final var verifier = randomVerifier();
        final var authorizeUrl = authServer.issuer() + "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + encode(REDIRECT_URI) + "&scope=" + encode("openid documents.read")
                + "&state=xyz&code_challenge=" + s256(verifier) + "&code_challenge_method=S256";
        final String code;
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            code = signInAndCaptureCode(browser, authorizeUrl);
        }

        final var credentials = Base64.getEncoder().encodeToString(
                (clientId + ":" + authServer.clientSecret()).getBytes(StandardCharsets.UTF_8));
        final var request = HttpRequest.newBuilder(URI.create(authServer.issuer() + "/oauth2/token"))
                .header("Authorization", "Basic " + credentials)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code&code=" + encode(code)
                        + "&redirect_uri=" + encode(REDIRECT_URI) + "&code_verifier=" + verifier))
                .build();
        final var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(HTTP_OK, response.statusCode(), response.body());
        final var matcher = ACCESS_TOKEN.matcher(response.body());
        assertNotNull(matcher.find() ? matcher.group(1) : null, "the token endpoint answers with an access token");
        return matcher.group(1);
    }

    /**
     * Signs the demo user in and returns the authorization code that the server sends to the redirect URI. The
     * request to that URI is intercepted, so no client has to listen there.
     *
     * @param browser      the browser.
     * @param authorizeUrl authorization request URL.
     * @return the authorization code.
     */
    private static String signInAndCaptureCode(final Browser browser, final String authorizeUrl) {
        final var page = browser.newPage();
        page.route(REDIRECT_URI + "**", Route::abort);
        page.navigate(authorizeUrl);

        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
        page.fill("#username", "demo");
        page.fill("#password", authServer.demoPassword());
        final var redirect = page.waitForRequest(REDIRECT_URI + "**", () -> page.click("button[type=submit]"));

        final var query = URI.create(redirect.url()).getRawQuery();
        for (final var pair : query.split("&")) {
            if (pair.startsWith("code=")) {
                return pair.substring("code=".length());
            }
        }
        throw new IllegalStateException("The redirect carries no authorization code: " + redirect.url());
    }

    /**
     * Lists the documents with a bearer token.
     *
     * @param token the access token.
     * @return the HTTP status of the answer.
     * @throws Exception if the request fails.
     */
    private static int listDocuments(final String token) throws Exception {
        return listDocuments(documentsUri(), token);
    }

    /**
     * Lists the documents of a resource server with a bearer token.
     *
     * @param uri   URI of the documents endpoint.
     * @param token the access token.
     * @return the HTTP status of the answer.
     * @throws Exception if the request fails.
     */
    private static int listDocuments(final URI uri, final String token) throws Exception {
        final var request = HttpRequest.newBuilder(uri).header("Authorization", "Bearer " + token)
                .GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    /**
     * Returns the URI of the documents endpoint.
     *
     * @return the URI.
     */
    private static URI documentsUri() {
        return URI.create("http://localhost:" + resourcePort + "/api/documents");
    }

    /**
     * Returns the URI of the documents endpoint of the opaque-token resource server.
     *
     * @return the URI.
     */
    private static URI opaqueUri() {
        return URI.create("http://localhost:" + opaquePort + "/api/documents");
    }

    /**
     * Registers a copy of the seeded {@code bff} client under another id, with the same secret.
     *
     * @param clientId       id of the copy.
     * @param clientSettings SQL expression of the copy's client settings.
     * @param tokenSettings  SQL expression of the copy's token settings.
     * @throws Exception if the statement cannot be run.
     */
    private static void copyClient(final String clientId, final String clientSettings, final String tokenSettings)
            throws Exception {
        authServer.sql("INSERT INTO oauth2_registered_client (id, client_id, client_secret, client_name, "
                + "client_authentication_methods, authorization_grant_types, redirect_uris, scopes, "
                + "client_settings, token_settings) SELECT gen_random_uuid()::text, '" + clientId
                + "', client_secret, client_name, client_authentication_methods, authorization_grant_types, "
                + "redirect_uris, scopes, " + clientSettings + ", " + tokenSettings
                + " FROM oauth2_registered_client WHERE client_id = '" + ACCEPTED_CLIENT + "'");
    }

    /**
     * Generates a PKCE code verifier.
     *
     * @return the verifier.
     */
    private static String randomVerifier() {
        final var bytes = new byte[VERIFIER_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Computes the S256 PKCE code challenge of a verifier.
     *
     * @param verifier code verifier.
     * @return the code challenge.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    private static String s256(final String verifier) throws NoSuchAlgorithmException {
        final var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /**
     * URL-encodes a value.
     *
     * @param value the value.
     * @return the encoded value.
     */
    private static String encode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
