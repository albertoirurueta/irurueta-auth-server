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

import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Route;
import com.microsoft.playwright.TimeoutError;
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
import tools.jackson.databind.json.JsonMapper;

/**
 * Obtains the access token of the demo user the way a client application does: the authorization code flow with
 * PKCE, with the user signing in in headless Chromium. The redirect to the client is intercepted, so no client
 * application has to listen at the redirect URI.
 */
final class UserTokenFlow {

    /** Number of random bytes of a PKCE code verifier. */
    private static final int VERIFIER_BYTES = 32;

    /** Longest wait for a page transition, in milliseconds. */
    private static final double PAGE_TIMEOUT_MILLIS = 30_000;

    /** Longest wait for the consent page, in milliseconds, before assuming the consent was granted earlier. */
    private static final double CONSENT_WAIT_MILLIS = 5_000;

    /** HTTP status of a successful response. */
    private static final int HTTP_OK = 200;

    /** Mapper of the token endpoint's answer. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /**
     * Not instantiable.
     */
    private UserTokenFlow() {
    }

    /**
     * Runs the flow for the demo user with the seeded {@code bff} client and returns the access token.
     *
     * @param authServer  the running server.
     * @param redirectUri the redirect URI registered for the {@code bff} client (nothing listens there).
     * @param scope       space separated scopes to request.
     * @return the access token of the user.
     * @throws Exception if a step of the flow fails.
     */
    static String bffAccessToken(final RunningAuthServer authServer, final String redirectUri, final String scope)
            throws Exception {
        final var clientId = "bff";
        final var verifier = randomVerifier();
        final var authorizeUrl = authServer.issuer() + "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + encode(redirectUri) + "&scope=" + encode(scope)
                + "&state=xyz&code_challenge=" + s256(verifier) + "&code_challenge_method=S256";
        final String code;
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            code = signInAndCaptureCode(browser.newPage(), authServer, redirectUri, authorizeUrl);
        }
        final var credentials = Base64.getEncoder().encodeToString(
                (clientId + ":" + authServer.clientSecret()).getBytes(StandardCharsets.UTF_8));
        final var request = HttpRequest.newBuilder(URI.create(authServer.issuer() + "/oauth2/token"))
                .header("Authorization", "Basic " + credentials)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code&code=" + encode(code)
                        + "&redirect_uri=" + encode(redirectUri) + "&code_verifier=" + verifier))
                .build();
        final var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(HTTP_OK, response.statusCode(), "token endpoint answer to the code exchange");
        return JSON.readTree(response.body()).get("access_token").asString();
    }

    /**
     * Signs the demo user in and returns the authorization code the server sends to the redirect URI.
     *
     * @param page         the browser page.
     * @param authServer   the running server.
     * @param redirectUri  the redirect URI whose request is intercepted.
     * @param authorizeUrl authorization request URL.
     * @return the authorization code.
     */
    private static String signInAndCaptureCode(final Page page, final RunningAuthServer authServer,
                                               final String redirectUri, final String authorizeUrl) {
        page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
        page.route(redirectUri + "**", Route::abort);
        page.navigate(authorizeUrl);
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
        page.fill("#username", "demo");
        page.fill("#password", authServer.demoPassword());
        final var redirect = page.waitForRequest(redirectUri + "**", () -> {
            page.click("button[type=submit]");
            allowWhenAsked(page, authServer);
        });
        for (final var pair : URI.create(redirect.url()).getRawQuery().split("&")) {
            if (pair.startsWith("code=")) {
                return pair.substring("code=".length());
            }
        }
        throw new IllegalStateException("The redirect carries no authorization code: " + redirect.url());
    }

    /**
     * Allows the requested scopes when the consent page is shown.
     *
     * @param page       the page of the browser, after the credentials were submitted.
     * @param authServer the running server.
     */
    private static void allowWhenAsked(final Page page, final RunningAuthServer authServer) {
        try {
            page.waitForURL(url -> url.startsWith(authServer.issuer() + "/oauth2/consent"),
                    new Page.WaitForURLOptions().setTimeout(CONSENT_WAIT_MILLIS));
        } catch (final TimeoutError notAsked) {
            return;
        }
        page.click("#allow");
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
