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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
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
 *
 * <p>Every response the page receives during the whole flow, sign-out included, is recorded and scanned for tokens:
 * bodies, the web storages and the cookies must never contain one. Response headers and URLs are scanned too, with
 * exactly two exclusions, both parts of the RP-initiated logout: the {@code Location} header of the {@code 302} that
 * answers {@code POST /bff/logout}, and the URL of the {@code /connect/logout} request the browser then makes. They
 * carry the ID token as {@code id_token_hint}, as OpenID Connect RP-Initiated Logout prescribes, in a top-level
 * navigation started by a form submission, which no script of the page can read. The test asserts that this
 * navigation happened, so the exclusions never hide a different flow.
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

    /** HTTP status of a redirect. */
    private static final int HTTP_FOUND = 302;

    /** Name of the response header that carries the target of a redirect (lower case, as Playwright reports it). */
    private static final String LOCATION = "location";

    /** Authentication context class the resource server asks for before a deletion. */
    private static final String STEP_UP_ACR = "urn:irurueta:acr:mfa";

    /** Maximum age, in seconds, of the authentication the resource server accepts before a deletion. */
    private static final int STEP_UP_MAX_AGE_SECONDS = 300;

    /**
     * Script run in the SPA page that deletes a document through the BFF the way a script of the SPA would (session
     * cookie and the CSRF token in the {@code X-XSRF-TOKEN} header) and returns the status and the body of the answer.
     */
    private static final String DELETE_DOCUMENT_SCRIPT = """
            async () => {
                const entry = document.cookie.split('; ').find((cookie) => cookie.startsWith('XSRF-TOKEN='));
                const token = decodeURIComponent(entry.substring('XSRF-TOKEN='.length));
                const response = await fetch('/api/documents/missing', {method: 'DELETE', credentials: 'same-origin',
                    headers: {'X-XSRF-TOKEN': token,
                    Accept: 'application/json, application/problem+json'}});
                return {status: response.status, body: await response.text()};
            }
            """;

    /** Path of the sign-out of the BFF. */
    private static final String BFF_LOGOUT_PATH = "/bff/logout";

    /** Path of the RP-initiated logout (end session endpoint) of the authorization server. */
    private static final String END_SESSION_PATH = "/connect/logout";

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
        bffArguments.add("--bff.resource-server.base-uri=http://localhost:" + resourcePort);
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
     * checks that the browser lands back on the signed-out SPA and that the protected calls are then refused, and
     * scans everything the browser received, before and after the sign-out, for tokens.
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

            final var issued = issuedTokens();
            assertSessionCookieIsHardened(page, context, observed);
            assertNoTokenReachedTheBrowser(page, context, observed, issued);

            page.click("#sign-out");
            page.waitForSelector("#signed-out:not([hidden])");
            assertEquals(bffUrl + "/", page.url(), "the browser is back on the SPA, not on the login page");
            assertTrue(page.isHidden("#profile"));
            assertRpInitiatedLogoutHappened(observed);
            assertEquals(HTTP_UNAUTHORIZED, context.request().get(bffUrl + "/api/documents").status());
            assertEquals(HTTP_UNAUTHORIZED, context.request().get(bffUrl + "/bff/user").status());
            assertEquals(0, authenticatedSessions());

            issued.addAll(issuedTokens());
            assertNoTokenReachedTheBrowser(page, context, observed, issued);
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
     * Signs in with a password only and deletes a document through the BFF. The BFF must ask the resource server with
     * the {@code documents.delete} scope (without it the answer would be {@code 403}), and the resource server's
     * step-up challenge (RFC 9470) must reach the SPA as a {@code step-up-required} problem. Starting the login with
     * its values must then send the browser to the second-factor page of the authorization server, which proves that
     * {@code acr_values} and {@code max_age} reached the authorization request.
     *
     * @throws Exception if a step of the flow fails.
     */
    @Test
    void documentDelete_whenSignInIsNotStrongEnough_asksForStepUpThroughTheLogin() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch();
             var context = browser.newContext()) {
            final var page = context.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
            // a user of its own: the consent the other tests grant to demo would otherwise skip the consent page
            final var username = "step-up-" + UUID.randomUUID();
            authServer.createUserLikeDemo(username);

            signIn(page, username);
            consent(page, "#allow");
            page.waitForSelector("#profile:not([hidden])");

            final var answer = (Map<?, ?>) page.evaluate(DELETE_DOCUMENT_SCRIPT);

            assertEquals(HTTP_UNAUTHORIZED, ((Number) answer.get("status")).intValue(), String.valueOf(answer));
            final var body = String.valueOf(answer.get("body"));
            assertTrue(body.contains("\"urn:problem:documents:step-up-required\""), body);
            assertTrue(body.contains("\"acrValues\":\"" + STEP_UP_ACR + "\""), body);
            assertTrue(body.contains("\"maxAge\":" + STEP_UP_MAX_AGE_SECONDS), body);

            page.navigate(bffUrl + "/bff/login?returnTo=%2F&acrValues=" + STEP_UP_ACR + "&maxAge="
                    + STEP_UP_MAX_AGE_SECONDS);
            page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login/second-factor"));
        }
    }

    /**
     * Opens the SPA, which shows its signed-out state without leaving the page, clicks <em>Sign in</em> and signs the
     * demo user in on the login page of the authorization server.
     *
     * @param page the page of the browser.
     */
    private static void signIn(final Page page) {
        signIn(page, "demo");
    }

    /**
     * Opens the SPA, clicks <em>Sign in</em> and signs a user that shares the demo user's password in on the login
     * page of the authorization server, up to its consent page.
     *
     * @param page     the page of the browser.
     * @param username name of the user.
     */
    private static void signIn(final Page page, final String username) {
        page.navigate(bffUrl + "/");
        page.waitForSelector("#signed-out:not([hidden])");
        assertEquals(bffUrl + "/", page.url(), "the first visit does not start the sign-in by itself");
        page.click("#sign-in");
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
        page.fill("#username", username);
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
     * Reads every token value the authorization server has issued so far.
     *
     * @return the token values, in a mutable set.
     * @throws Exception if the database cannot be queried.
     */
    private static Set<String> issuedTokens() throws Exception {
        return new LinkedHashSet<>(authServer.query(ISSUED_TOKENS));
    }

    /**
     * Records every response the page receives: method, URL, headers (including {@code Set-Cookie}) and body.
     *
     * @param page the page of the browser.
     * @return the recorded responses, in arrival order; filled as the page works.
     */
    private static List<ObservedResponse> recordResponses(final Page page) {
        final var observed = new ArrayList<ObservedResponse>();
        page.onResponse(response -> observed.add(ObservedResponse.of(response)));
        return observed;
    }

    /**
     * Asserts that the sign-out went through the RP-initiated logout: {@code POST /bff/logout} answered a redirect to
     * the end session endpoint with an ID token hint, and the browser followed it. These two are what the token scan
     * excludes from its header and URL checks.
     *
     * @param observed the responses recorded during the flow.
     */
    private static void assertRpInitiatedLogoutHappened(final List<ObservedResponse> observed) {
        final var logout = observed.stream().filter(BffEndToEndIT::isBffLogout).findFirst().orElseThrow();
        assertEquals(HTTP_FOUND, logout.status());
        final var location = logout.headers().get(LOCATION);
        assertTrue(location.startsWith(authServer.issuer() + END_SESSION_PATH), location);
        assertTrue(location.contains("id_token_hint="), "the end session request carries the ID token hint");
        assertTrue(observed.stream().anyMatch(BffEndToEndIT::isEndSessionRequest),
                "the browser followed the redirect to the end session endpoint");
    }

    /**
     * Asserts that the session cookie is {@code HttpOnly}, {@code Secure} and {@code SameSite=Lax}, and not readable by
     * scripts, while the user is signed in.
     *
     * @param page     the page of the browser, on the SPA.
     * @param context  the browser context.
     * @param observed the responses recorded so far.
     */
    private static void assertSessionCookieIsHardened(
            final Page page, final BrowserContext context, final List<ObservedResponse> observed) {
        assertFalse(String.valueOf(page.evaluate("document.cookie")).contains(SESSION_COOKIE),
                "the session cookie is not readable by scripts");
        final Cookie session = context.cookies().stream().filter(cookie -> SESSION_COOKIE.equals(cookie.name))
                .findFirst().orElseThrow();
        assertTrue(session.httpOnly, "HttpOnly");
        assertTrue(session.secure, "Secure");
        assertEquals(SameSiteAttribute.LAX, session.sameSite);
        assertTrue(observed.stream().anyMatch(response -> response.url().contains("/bff/user")));
        assertTrue(observed.stream().anyMatch(response -> response.url().contains("/api/documents")
                && response.body().contains("[]")), "the documents response was scanned");
        assertEquals(HTTP_OK, context.request().get(bffUrl + "/bff/user").status());
    }

    /**
     * Asserts that no token is visible to the browser: not in the web storages, the cookies (the script-readable ones
     * and the cookie jar as a whole) or any recorded response (body, headers and URL, with the two exclusions of the
     * RP-initiated logout described on this class).
     *
     * @param page     the page of the browser, on the SPA.
     * @param context  the browser context.
     * @param observed the responses recorded so far.
     * @param issued   the token values the authorization server has issued.
     */
    private static void assertNoTokenReachedTheBrowser(final Page page, final BrowserContext context,
            final List<ObservedResponse> observed, final Set<String> issued) {
        assertTrue(issued.stream().anyMatch(token -> JWT_SHAPE.matcher(token).matches()),
                "the authorization server issued a JWT, so the scan pattern is meaningful");
        assertTrue(observed.size() > 1, "responses were recorded");

        final var sources = new LinkedHashMap<String, String>();
        for (var index = 0; index < observed.size(); index++) {
            final var response = observed.get(index);
            final var label = "response #" + index + " (" + response.method() + " " + response.status() + ")";
            if (!isEndSessionRequest(response)) {
                sources.put(label + " URL", response.url());
            }
            final var headers = new HashMap<>(response.headers());
            if (isBffLogout(response)) {
                headers.remove(LOCATION);
            }
            sources.put(label + " headers", headers.toString());
            sources.put(label + " body", response.body());
        }
        sources.put("localStorage", String.valueOf(page.evaluate("JSON.stringify(Object.entries(localStorage))")));
        sources.put("sessionStorage",
                String.valueOf(page.evaluate("JSON.stringify(Object.entries(sessionStorage))")));
        sources.put("document.cookie", String.valueOf(page.evaluate("document.cookie")));
        context.cookies().forEach(cookie -> sources.put("cookie " + cookie.name, cookie.value));
        sources.forEach((label, content) -> {
            assertFalse(JWT_SHAPE.matcher(content).find(), "JWT-shaped value in " + label);
            issued.forEach(token -> assertFalse(content.contains(token), "an issued token is visible in " + label));
        });
    }

    /**
     * Tells whether a response answers the sign-out form of the SPA.
     *
     * @param response a recorded response.
     * @return {@code true} for the response to {@code POST /bff/logout}.
     */
    private static boolean isBffLogout(final ObservedResponse response) {
        return "POST".equals(response.method()) && (bffUrl + BFF_LOGOUT_PATH).equals(response.url());
    }

    /**
     * Tells whether a response answers the request to the end session endpoint of the authorization server.
     *
     * @param response a recorded response.
     * @return {@code true} for the response to {@code /connect/logout}.
     */
    private static boolean isEndSessionRequest(final ObservedResponse response) {
        return response.url().startsWith(authServer.issuer() + END_SESSION_PATH);
    }

    /**
     * A response the page received, captured when it arrived.
     *
     * @param method  method of the request.
     * @param url     URL of the request.
     * @param status  HTTP status.
     * @param headers response headers, names in lower case (including {@code Set-Cookie}).
     * @param body    the body, or a marker when the browser has none (redirects, navigated-away documents).
     */
    private record ObservedResponse(String method, String url, int status, Map<String, String> headers,
            String body) {

        /**
         * Captures a response.
         *
         * @param response the response.
         * @return its recorded form.
         */
        static ObservedResponse of(final Response response) {
            return new ObservedResponse(response.request().method(), response.url(), response.status(),
                    Map.copyOf(response.allHeaders()), bodyOf(response));
        }

        /**
         * Reads the body of a response.
         *
         * @param response the response.
         * @return the body, or a marker when the browser has none.
         */
        private static String bodyOf(final Response response) {
            try {
                return response.text();
            } catch (final PlaywrightException unavailable) {
                // redirects and navigated-away documents have no body to read: their headers are still scanned
                return "(no body)";
            }
        }
    }
}
