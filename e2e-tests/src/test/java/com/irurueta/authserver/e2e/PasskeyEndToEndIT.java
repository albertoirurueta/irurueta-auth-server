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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * End-to-end test of the passkeys with a real browser: the packaged {@code auth-server} and {@code bff} run on random
 * ports against a PostgreSQL container, and headless Chromium gets a CDP virtual authenticator (CTAP2, internal,
 * resident key, user verified) so that the script of the pages runs the real WebAuthn ceremonies. The first scenario
 * registers a passkey from the account page and signs in through the BFF with it alone, clicking its button; the
 * second signs in with the password and completes the second-factor page with the passkey; the third lets the browser
 * offer the passkey in the username field. Each scenario has a user of its own, copied from the demo user. The
 * claims are read from the access token the authorization server stored, so the BFF never has to expose it.
 */
class PasskeyEndToEndIT {

    /** Matches the log line printed once the BFF is up. */
    private static final Pattern BFF_STARTED = Pattern.compile("Started BffApplication in");

    /** Query that returns the most recently issued access token. */
    private static final String LATEST_ACCESS_TOKEN = "SELECT access_token_value FROM oauth2_authorization"
            + " WHERE access_token_value IS NOT NULL ORDER BY access_token_issued_at DESC LIMIT 1";

    /** Longest wait for a page transition, in milliseconds. */
    private static final double PAGE_TIMEOUT_MILLIS = 30_000;

    /** Number of segments of a JSON Web Token. */
    private static final int JWT_SEGMENTS = 3;

    /** Index of the payload among the segments of a JSON Web Token. */
    private static final int PAYLOAD_INDEX = 1;

    /** Name of the claim with the authentication methods. */
    private static final String AMR = "amr";

    /** Path of the passkeys account page. */
    private static final String ACCOUNT_PATH = "/account/passkeys";

    /** Path of the second-factor page. */
    private static final String SECOND_FACTOR_PATH = "/login/second-factor";

    /** Path of the consent page. */
    private static final String CONSENT_PATH = "/oauth2/consent";

    /** Name of the user of the first scenario. */
    private static final String PRIMARY_USER = "passkey-primary";

    /** Name of the user of the second scenario. */
    private static final String SECOND_FACTOR_USER = "passkey-second";

    /** Name of the user of the autofill scenario. */
    private static final String AUTOFILL_USER = "passkey-autofill";

    /** Selector of what the account page shows once it lists a passkey. */
    private static final String LISTED_PASSKEY = ".passkey-list li";

    /** Selector of the button that signs in with a passkey. */
    private static final String PASSKEY_BUTTON = "[data-passkey-button]";

    /** The packaged authorization server and its database. */
    private static RunningAuthServer authServer;

    /** The packaged backend-for-frontend. */
    private static ManagedApp bff;

    /** Base URL of the BFF, which also serves the SPA. */
    private static String bffUrl;

    /**
     * Starts the database, the authorization server and the BFF, registering the BFF's real address in the
     * {@code bff} client.
     *
     * @throws Exception if an application or the container cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        final var bffPort = RunningAuthServer.freePort();
        bffUrl = "http://localhost:" + bffPort;
        authServer = RunningAuthServer.start(List.of(
                "--authserver.clients.bff.redirect-uris=" + bffUrl + "/login/oauth2/code/bff",
                "--authserver.clients.bff.post-logout-redirect-uris=" + bffUrl + "/"));
        final var bffArguments = new ArrayList<>(authServer.bffDatabaseArguments());
        bffArguments.add("--server.port=" + bffPort);
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
        if (authServer != null) {
            authServer.close();
        }
    }

    /**
     * Registers a passkey from the account page, signs out, and signs in through the BFF with the passkey alone: the
     * access token reports the hardware-key method and no password.
     *
     * @throws Exception if a step of the flow fails.
     */
    @Test
    void signIn_whenUserRegisteredAPasskey_usesItAsTheOnlyFactor() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch();
             var context = browser.newContext()) {
            final var page = context.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
            addVirtualAuthenticator(context, page);
            withoutPasskeyAutofill(page);
            authServer.createUserLikeDemo(PRIMARY_USER);

            registerAPasskey(page, PRIMARY_USER, "Primary key");
            context.clearCookies();
            signInThroughTheBff(page);
            page.click(PASSKEY_BUTTON);
            completeAuthorization(page, PRIMARY_USER);

            final var methods = latestAmr();
            assertTrue(methods.contains("hwk"), methods.toString());
            assertFalse(methods.contains("pwd"), methods.toString());
        }
    }

    /**
     * Registers a passkey, signs out, signs in with the password, and completes the second-factor page with the
     * passkey: the access token reports the password, the hardware key and the multi-factor method.
     *
     * @throws Exception if a step of the flow fails.
     */
    @Test
    void signIn_whenUserHasAPasskey_passwordThenPasskeyReportsBothFactors() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch();
             var context = browser.newContext()) {
            final var page = context.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
            addVirtualAuthenticator(context, page);
            withoutPasskeyAutofill(page);
            authServer.createUserLikeDemo(SECOND_FACTOR_USER);

            registerAPasskey(page, SECOND_FACTOR_USER, "Second factor key");
            context.clearCookies();
            signInThroughTheBff(page);
            page.fill("#username", SECOND_FACTOR_USER);
            page.fill("#password", authServer.demoPassword());
            page.click("button[type=submit]");
            page.waitForURL(url -> url.startsWith(authServer.issuer() + SECOND_FACTOR_PATH));
            page.click(PASSKEY_BUTTON);
            completeAuthorization(page, SECOND_FACTOR_USER);

            final var methods = latestAmr();
            assertTrue(methods.containsAll(List.of("pwd", "hwk", "mfa")), methods.toString());
        }
    }

    /**
     * Registers a passkey, signs out, and opens the login page of a browser that offers the passkeys in the username
     * field (conditional mediation, which Chromium with a virtual authenticator completes by itself): the sign-in
     * finishes without a click on the passkey button.
     *
     * @throws Exception if a step of the flow fails.
     */
    @Test
    void signIn_whenBrowserOffersPasskeyAutofill_signsInWithoutClicking() throws Exception {
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch();
             var context = browser.newContext()) {
            final var page = context.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
            addVirtualAuthenticator(context, page);
            authServer.createUserLikeDemo(AUTOFILL_USER);

            registerAPasskey(page, AUTOFILL_USER, "Autofill key");
            context.clearCookies();
            signInThroughTheBff(page);
            completeAuthorization(page, AUTOFILL_USER);

            final var methods = latestAmr();
            assertTrue(methods.contains("hwk"), methods.toString());
            assertFalse(methods.contains("pwd"), methods.toString());
        }
    }

    /**
     * Makes the page behave like a browser without conditional mediation, so that the login page does not start a
     * passkey sign-in by itself and the tests drive the passkey button or the password form.
     *
     * @param page the page of the browser.
     */
    private static void withoutPasskeyAutofill(final Page page) {
        page.addInitScript("window.PublicKeyCredential.isConditionalMediationAvailable = undefined;");
    }

    /**
     * Gives the page a virtual authenticator that behaves like a platform passkey: CTAP2, internal transport, able
     * to store discoverable credentials, and user verified.
     *
     * @param context the browser context.
     * @param page    the page that gets the authenticator.
     */
    private static void addVirtualAuthenticator(final BrowserContext context, final Page page) {
        final var session = context.newCDPSession(page);
        session.send("WebAuthn.enable");
        final var options = new JsonObject();
        options.addProperty("protocol", "ctap2");
        options.addProperty("transport", "internal");
        options.addProperty("hasResidentKey", true);
        options.addProperty("hasUserVerification", true);
        options.addProperty("isUserVerified", true);
        options.addProperty("automaticPresenceSimulation", true);
        final var parameters = new JsonObject();
        parameters.add("options", options);
        session.send("WebAuthn.addVirtualAuthenticator", parameters);
    }

    /**
     * Signs a user in on the login page of the authorization server and registers a passkey from the account page.
     * The page reloads after the registration and, as the account now has a passkey that this session has not
     * presented, the server asks for the second factor before showing the list: the passkey just registered
     * completes it, and the page then lists the passkey.
     *
     * @param page     the page of the browser.
     * @param username the user.
     * @param label    name given to the passkey.
     */
    private static void registerAPasskey(final Page page, final String username, final String label) {
        page.navigate(authServer.issuer() + "/login");
        page.fill("#username", username);
        page.fill("#password", authServer.demoPassword());
        page.click("button[type=submit]");
        page.waitForURL(url -> !url.contains("/login"));
        page.navigate(authServer.issuer() + ACCOUNT_PATH);
        page.fill("#passkey-label", label);
        page.click("[data-passkey-register-button]");
        page.locator(LISTED_PASSKEY + ", " + PASSKEY_BUTTON).first().waitFor();
        if (page.locator(PASSKEY_BUTTON).count() > 0) {
            page.click(PASSKEY_BUTTON);
        }
        page.waitForURL(url -> url.startsWith(authServer.issuer() + ACCOUNT_PATH));
        assertEquals(label, page.locator(LISTED_PASSKEY + " strong").first().textContent());
    }

    /**
     * Opens the SPA, clicks <em>Sign in</em> and waits for the login page of the authorization server.
     *
     * @param page the page of the browser.
     */
    private static void signInThroughTheBff(final Page page) {
        page.navigate(bffUrl + "/");
        page.waitForSelector("#signed-out:not([hidden])");
        page.click("#sign-in");
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
    }

    /**
     * Waits until the browser leaves the sign-in pages, answers the consent page when it is shown (it is skipped when
     * an earlier sign-in already granted it), and waits for the SPA to show the profile.
     *
     * @param page     the page of the browser.
     * @param username the user the profile must show.
     */
    private static void completeAuthorization(final Page page, final String username) {
        page.waitForURL(url -> url.startsWith(authServer.issuer() + CONSENT_PATH) || url.startsWith(bffUrl));
        if (page.url().startsWith(authServer.issuer() + CONSENT_PATH)) {
            page.click("#allow");
            page.waitForURL(url -> url.startsWith(bffUrl));
        }
        page.waitForSelector("#profile:not([hidden])");
        assertEquals(username, page.textContent("#profile-subject"));
    }

    /**
     * Reads the {@code amr} claim of the access token issued last.
     *
     * @return the authentication methods.
     * @throws Exception if the database cannot be queried.
     */
    private static List<String> latestAmr() throws Exception {
        final var token = authServer.query(LATEST_ACCESS_TOKEN).getFirst();
        final var segments = token.split("\\.");
        assertEquals(JWT_SEGMENTS, segments.length, "the access token is a JWT");
        final var claims = JsonParser.parseString(
                new String(Base64.getUrlDecoder().decode(segments[PAYLOAD_INDEX]), StandardCharsets.UTF_8))
                .getAsJsonObject();
        return claims.getAsJsonArray(AMR).asList().stream().map(JsonElement::getAsString).toList();
    }
}
