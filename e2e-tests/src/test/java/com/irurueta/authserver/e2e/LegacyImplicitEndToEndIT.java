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

import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/**
 * End-to-end test of the legacy implicit flow with the packaged {@code auth-server} running under the
 * {@code dev,legacy-implicit} profiles: headless Chromium opens the demo page the profile serves, signs the demo user
 * in, and the page shows the claims of the token it received in the URL fragment and that the {@code state} it sent
 * came
 * back. The same request from any other client ({@code spa-public}, a public client of the authorization code flow) is
 * answered with an error and no token.
 */
class LegacyImplicitEndToEndIT {

    /** Redirect URI of the seeded {@code bff} client; the server needs one to seed it. */
    private static final String BFF_REDIRECT_URI = "http://127.0.0.1:8099/callback";

    /** Client of the authorization code flow that must not get a token from the implicit flow. */
    private static final String SPA_PUBLIC = "spa-public";

    /** HTTP status of a bad request. */
    private static final int HTTP_BAD_REQUEST = 400;

    /** Longest wait for a page transition, in milliseconds. */
    private static final double PAGE_TIMEOUT_MILLIS = 30_000;

    /** Mapper of the claims the page shows. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** The packaged authorization server and its database. */
    private static RunningAuthServer authServer;

    /**
     * Starts the authorization server with the legacy implicit profile, whose client redirects to the demo page of
     * this server ({@code spa-public} is seeded by the server).
     *
     * @throws Exception if the server cannot be started.
     */
    @BeforeAll
    static void startAuthServer() throws Exception {
        authServer = RunningAuthServer.start(List.of(
                // the command-line values of a property are joined, so this adds the profile to the default dev one
                "--spring.profiles.active=legacy-implicit",
                "--authserver.clients.bff.redirect-uris=" + BFF_REDIRECT_URI,
                "--authserver.legacy-implicit.redirect-uri=http://localhost:${server.port}/legacy-implicit/"));
    }

    /** Stops the server and its database. */
    @AfterAll
    static void stopAuthServer() {
        if (authServer != null) {
            authServer.close();
        }
    }

    /**
     * Verifies the whole flow: the page sends the user to sign in, receives the token in the fragment, checks the
     * {@code state}, clears the fragment and shows the claims of the token.
     *
     * @throws Exception if the browser fails.
     */
    @Test
    void legacyImplicit_whenTheDemoUserSignsIn_thePageShowsTheTokenClaims() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            final var page = browser.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);

            page.navigate(demoPageUrl());
            page.click("#sign-in");
            page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
            page.fill("#username", "demo");
            page.fill("#password", authServer.demoPassword());
            page.click("button[type=submit]");
            page.waitForSelector("#claims:not([hidden])");

            final var status = page.textContent("#status");
            assertTrue(status.startsWith("Token received"), status);
            assertFalse(status.contains("Refused"), "the state of the response matched the request: " + status);
            final var claims = JSON.readTree(page.textContent("#claims"));
            assertEquals("demo", claims.get("sub").asString());
            assertTrue(claims.get("aud").toString().contains(ClientAdminApi.RESOURCE_SERVER_AUDIENCE),
                    claims.toString());
            assertTrue(claims.get("scope").toString().contains(ClientAdminApi.DOCUMENTS_READ), claims.toString());
            assertFalse(claims.has("cnf"), "the legacy token is a plain bearer token");
            assertFalse(page.url().contains("#"), "the page clears the token from the address: " + page.url());
        }
    }

    /**
     * Verifies that the same request made as {@code spa-public} is refused with {@code 400} (the generic error page
     * hides the {@code unsupported_response_type} code, which {@code ImplicitRejectedIT} pins) and never sends the
     * browser to sign in or back to the client with a token.
     *
     * @throws Exception if the browser fails.
     */
    @Test
    void legacyImplicit_whenAnotherClientAsksForAToken_theRequestIsRefused() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            final var page = browser.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
            page.navigate(demoPageUrl());
            page.evaluate("document.getElementById('sign-in').dataset.clientId = '" + SPA_PUBLIC + "'");

            final var response = page.waitForResponse(
                    answer -> answer.url().startsWith(authServer.issuer() + "/oauth2/authorize"),
                    () -> page.click("#sign-in"));

            assertEquals(HTTP_BAD_REQUEST, response.status());
            assertFalse(response.url().isEmpty());
            assertFalse(page.url().contains("access_token"), page.url());
            assertFalse(page.url().startsWith(authServer.issuer() + "/login"), page.url());
            assertDemoClientStillWorks(page);
        }
    }

    /**
     * Verifies that, for the same page and server, the client the profile registers is not refused: its request reaches
     * the sign-in page.
     *
     * @param page the browser page.
     */
    private static void assertDemoClientStillWorks(final Page page) {
        page.navigate(demoPageUrl());
        page.click("#sign-in");
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
    }

    /**
     * Returns the address of the demo page the profile serves.
     *
     * @return the URL, which is also the redirect URI of the legacy client.
     */
    private static String demoPageUrl() {
        return authServer.issuer() + "/legacy-implicit/";
    }
}
