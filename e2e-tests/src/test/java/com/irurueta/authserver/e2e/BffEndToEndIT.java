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

import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.PlaywrightException;
import com.microsoft.playwright.Response;
import com.microsoft.playwright.options.Cookie;
import com.microsoft.playwright.options.SameSiteAttribute;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * End-to-end test of the single page application through the real servers: the packaged {@code auth-server},
 * {@code resource-server} and {@code bff} run on random ports against a PostgreSQL container, and the demo user
 * drives the SPA in headless Chromium. The {@code bff} client requires consent, so the flow goes through the login
 * and the consent pages. The browser reaches every application through {@code localhost}, where Chromium accepts the
 * {@code Secure} session cookie over plain HTTP.
 */
class BffEndToEndIT {

    /** Name of the session cookie of the BFF. */
    private static final String SESSION_COOKIE = "__Host-SESSION";

    /** Matches the log line printed once the BFF is up. */
    private static final Pattern BFF_STARTED = Pattern.compile("Started BffApplication in");

    /** Matches the log line printed once the resource server is up. */
    private static final Pattern RESOURCE_SERVER_STARTED = Pattern.compile("Started ResourceServerApplication in");

    /** Matches a JSON Web Token: three dot-separated base64url segments, the first one a JSON header. */
    private static final Pattern JWT_SHAPE = Pattern.compile("eyJ[\\w-]+\\.[\\w-]+\\.[\\w-]*");

    /** Query that returns every token value the authorization server has issued. */
    private static final String ISSUED_TOKENS = "SELECT access_token_value FROM oauth2_authorization"
            + " WHERE access_token_value IS NOT NULL UNION ALL SELECT refresh_token_value FROM oauth2_authorization"
            + " WHERE refresh_token_value IS NOT NULL UNION ALL SELECT oidc_id_token_value FROM oauth2_authorization"
            + " WHERE oidc_id_token_value IS NOT NULL";

    /** Query that counts the BFF sessions of an authenticated user. */
    private static final String AUTHENTICATED_SESSIONS =
            "SELECT count(*) FROM spring_session WHERE principal_name IS NOT NULL";

    /** Name of the database of the BFF. */
    private static final String BFF_DATABASE = "bff";

    /** Longest wait for a page transition, in milliseconds. */
    private static final double PAGE_TIMEOUT_MILLIS = 30_000;

    /** HTTP status of a successful response. */
    private static final int HTTP_OK = 200;

    /** HTTP status of an unauthorized response. */
    private static final int HTTP_UNAUTHORIZED = 401;

    /** The packaged authorization server and its database. */
    private static RunningAuthServer authServer;

    /** The packaged resource server. */
    private static ManagedApp resourceServer;

    /** The packaged backend-for-frontend. */
    private static ManagedApp bff;

    /** Base URL of the BFF, which also serves the SPA. */
    private static String bffUrl;

    /**
     * Starts the database and the three applications, registering the BFF's real address in the {@code bff} client.
     *
     * @throws Exception if an application or the container cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        final var bffPort = RunningAuthServer.freePort();
        final var resourcePort = RunningAuthServer.freePort();
        bffUrl = "http://localhost:" + bffPort;
        authServer = RunningAuthServer.start(List.of(
                "--authserver.clients.bff.redirect-uris=" + bffUrl + "/login/oauth2/code/bff",
                "--authserver.clients.bff.post-logout-redirect-uris=" + bffUrl + "/"));

        resourceServer = ManagedApp.start(RunningAuthServer.jar("resourceserver.jar"),
                List.of("--server.port=" + resourcePort), List.of("AUTH_ISSUER=" + authServer.issuer()));
        resourceServer.await(RESOURCE_SERVER_STARTED, RunningAuthServer.STARTUP_TIMEOUT);

        final var bffArguments = new ArrayList<>(authServer.bffDatabaseArguments());
        bffArguments.add("--server.port=" + bffPort);
        bffArguments.add("--bff.relay.target-uri=http://localhost:" + resourcePort);
        bff = ManagedApp.start(RunningAuthServer.jar("bff.jar"), bffArguments,
                List.of("AUTH_ISSUER=" + authServer.issuer(), "BFF_CLIENT_SECRET=" + authServer.clientSecret()));
        bff.await(BFF_STARTED, RunningAuthServer.STARTUP_TIMEOUT);
    }

    /** Stops the applications and the database. */
    @AfterAll
    static void stopApplications() {
        if (bff != null) {
            bff.stop();
        }
        if (resourceServer != null) {
            resourceServer.stop();
        }
        if (authServer != null) {
            authServer.close();
        }
    }

    /**
     * Signs in through the login and consent pages, reads the profile and the documents through the BFF, signs out,
     * and checks that the protected calls are then refused.
     *
     * @throws Exception if a step of the flow fails.
     */
    @Test
    void spa_whenUserSignsInAndOut_showsProfileAndDocumentsThenRefusesCalls() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch();
             var context = browser.newContext()) {
            final var page = context.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
            final var observed = recordResponses(page);

            signIn(page);
            consent(page, "#allow");

            page.waitForSelector("#profile:not([hidden])");
            assertEquals("demo", page.textContent("#profile-subject"));
            page.click("#load-documents");
            page.waitForSelector("#documents:not([hidden])");
            assertTrue(page.isHidden("#error"), "no error is shown when the documents are loaded");
            assertEquals(1, authenticatedSessions());

            assertNoTokenReachedTheBrowser(page, context, observed);

            page.click("#sign-out");
            page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
            assertEquals(HTTP_UNAUTHORIZED, context.request().get(bffUrl + "/api/documents").status());
            assertEquals(HTTP_UNAUTHORIZED, context.request().get(bffUrl + "/bff/user").status());
            assertEquals(0, authenticatedSessions());
        }
    }

    /**
     * Denies the consent and checks that the SPA reports the failed sign-in and that no session is created.
     *
     * @throws Exception if a step of the flow fails.
     */
    @Test
    void spa_whenUserDeniesConsent_showsSignInFailureAndCreatesNoSession() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch();
             var context = browser.newContext()) {
            final var page = context.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);

            signIn(page);
            consent(page, "#deny");

            page.waitForURL(url -> url.startsWith(bffUrl + "/?error=signin"));
            page.waitForSelector("#error:not([hidden])");
            assertTrue(page.textContent("#error").contains("Sign-in failed"), page.textContent("#error"));
            assertTrue(page.isHidden("#profile"));
            assertEquals(HTTP_UNAUTHORIZED, context.request().get(bffUrl + "/bff/user").status());
            assertEquals(0, authenticatedSessions());
        }
    }

    /**
     * Opens the SPA and signs the demo user in on the login page of the authorization server.
     *
     * @param page the page of the browser.
     */
    private static void signIn(final Page page) {
        page.navigate(bffUrl + "/");
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
        page.fill("#username", "demo");
        page.fill("#password", authServer.demoPassword());
        page.click("button[type=submit]");
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/oauth2/consent"));
    }

    /**
     * Answers the consent page.
     *
     * @param page     the page of the browser.
     * @param decision selector of the button that decides: {@code #allow} or {@code #deny}.
     */
    private static void consent(final Page page, final String decision) {
        page.click(decision);
        page.waitForURL(url -> url.startsWith(bffUrl));
    }

    /**
     * Counts the BFF sessions that belong to an authenticated user.
     *
     * @return the number of such sessions.
     * @throws Exception if the database cannot be queried.
     */
    private static int authenticatedSessions() throws Exception {
        return Integer.parseInt(authServer.query(BFF_DATABASE, AUTHENTICATED_SESSIONS).getFirst());
    }

    /**
     * Records every response the page receives (status line, headers including {@code Set-Cookie}, and body).
     *
     * @param page the page of the browser.
     * @return the recorded responses, keyed by a label; filled as the page works.
     */
    private static Map<String, String> recordResponses(final Page page) {
        final var observed = new LinkedHashMap<String, String>();
        page.onResponse(response -> observed.put(response.request().method() + " " + response.url() + " #"
                + observed.size(), describe(response)));
        return observed;
    }

    /**
     * Renders a response as text: its headers and, when the browser still has it, its body.
     *
     * @param response the response.
     * @return the text to scan.
     */
    private static String describe(final Response response) {
        final var text = new StringBuilder(response.allHeaders().toString());
        try {
            text.append('\n').append(response.text());
        } catch (final PlaywrightException unavailable) {
            // redirects and navigated-away documents have no body to read: their headers are still scanned
            text.append("\n(no body)");
        }
        return text.toString();
    }

    /**
     * Asserts that no token of the signed-in user is visible to the browser: not in the web storages, the cookies
     * (the script-readable ones and the cookie jar as a whole), the response bodies or the response headers; and that
     * the session cookie is {@code HttpOnly}, {@code Secure} and {@code SameSite=Lax}.
     *
     * @param page     the page of the browser, on the SPA.
     * @param context  the browser context.
     * @param observed the responses recorded so far.
     * @throws Exception if the issued tokens cannot be read from the database.
     */
    private static void assertNoTokenReachedTheBrowser(
            final Page page, final BrowserContext context, final Map<String, String> observed) throws Exception {
        final var issued = authServer.query(ISSUED_TOKENS);
        assertTrue(issued.stream().anyMatch(token -> JWT_SHAPE.matcher(token).matches()),
                "the authorization server issued a JWT, so the scan pattern is meaningful");
        assertTrue(observed.size() > 1, "responses were recorded");

        final var sources = new LinkedHashMap<String, String>(observed);
        sources.put("localStorage", String.valueOf(page.evaluate("JSON.stringify(Object.entries(localStorage))")));
        sources.put("sessionStorage",
                String.valueOf(page.evaluate("JSON.stringify(Object.entries(sessionStorage))")));
        sources.put("document.cookie", String.valueOf(page.evaluate("document.cookie")));
        context.cookies().forEach(cookie -> sources.put("cookie " + cookie.name, cookie.value));
        sources.forEach((label, content) -> {
            assertFalse(JWT_SHAPE.matcher(content).find(), "JWT-shaped value in " + label);
            issued.forEach(token -> assertFalse(content.contains(token), "an issued token is visible in " + label));
        });

        assertFalse(String.valueOf(page.evaluate("document.cookie")).contains(SESSION_COOKIE),
                "the session cookie is not readable by scripts");
        final Cookie session = context.cookies().stream().filter(cookie -> SESSION_COOKIE.equals(cookie.name))
                .findFirst().orElseThrow();
        assertTrue(session.httpOnly, "HttpOnly");
        assertTrue(session.secure, "Secure");
        assertEquals(SameSiteAttribute.LAX, session.sameSite);
        assertTrue(observed.keySet().stream().anyMatch(label -> label.contains("/bff/user")));
        assertTrue(observed.entrySet().stream().anyMatch(entry -> entry.getKey().contains("/api/documents")
                && entry.getValue().contains("[]")), "the documents response was scanned");
        assertEquals(HTTP_OK, context.request().get(bffUrl + "/bff/user").status());
    }
}
