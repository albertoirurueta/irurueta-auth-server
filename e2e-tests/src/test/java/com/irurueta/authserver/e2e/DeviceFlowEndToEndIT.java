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

import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * End-to-end test of the OAuth 2.0 device authorization grant (RFC 8628) with the packaged applications: the
 * {@code auth-server} (dev profile, which seeds the {@code device-client}) runs on a random port against PostgreSQL,
 * and the polling command line tool of the {@code service-client} runs from its own jar as a child process. The tool
 * prints a user code and a verification address; headless Chromium opens the complete address, signs the demo user in,
 * approves (or denies) the consent and the tool, which has been polling, ends with the tokens (or with the refusal).
 */
class DeviceFlowEndToEndIT {

    /** Longest wait for a page transition, in milliseconds. */
    private static final double PAGE_TIMEOUT_MILLIS = 30_000;

    /** Longest wait for the tool to print something that depends on the browser or on a polling round. */
    private static final Duration TOOL_TIMEOUT = Duration.ofSeconds(90);

    /** Longest wait for the tool to end once it has what it needs. */
    private static final Duration EXIT_TIMEOUT = Duration.ofSeconds(30);

    /** Matches the user code the tool prints. */
    private static final Pattern USER_CODE = Pattern.compile("^User code: (\\S+)");

    /** Matches the complete verification address the tool prints. */
    private static final Pattern COMPLETE_URI = Pattern.compile("^Verification URI \\(complete\\): (\\S+)");

    /** Matches the summary the tool prints when it obtained the tokens. */
    private static final Pattern COMPLETED = Pattern.compile("^Device flow completed: (.*)");

    /** Matches the access token the tool prints when asked to. */
    private static final Pattern ACCESS_TOKEN = Pattern.compile("^Access token: (\\S+)");

    /** Selector of the button that approves the consent. */
    private static final String ALLOW = "#allow";

    /** Selector of the button that denies the consent. */
    private static final String DENY = "#deny";

    /** Exit code of a tool that ended without error. */
    private static final int SUCCESS = 0;

    /** Position of the payload in a compact JWT. */
    private static final int PAYLOAD = 1;

    /** Mapper of the JSON of the token. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** The packaged authorization server and its database. */
    private static RunningAuthServer authServer;

    /**
     * Starts the authorization server.
     *
     * @throws Exception if the database or the server cannot be started.
     */
    @BeforeAll
    static void startAuthServer() throws Exception {
        authServer = RunningAuthServer.start();
    }

    /** Stops the server and its database. */
    @AfterAll
    static void stopAuthServer() {
        if (authServer != null) {
            authServer.close();
        }
    }

    /**
     * Runs the whole flow: the tool asks for a device code, the user approves it in the browser and the tool ends with
     * a bearer access token for the user, a refresh token and the scopes of the client.
     *
     * @throws Exception if the tool or the browser fails.
     */
    @Test
    void deviceFlow_whenTheUserApproves_theToolObtainsTheTokens() throws Exception {
        final var tool = startTool();
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            final var userCode = tool.await(USER_CODE, TOOL_TIMEOUT);
            final var verification = tool.await(COMPLETE_URI, TOOL_TIMEOUT);
            assertTrue(verification.contains(userCode), "The complete address carries the user code: " + verification);
            final var page = browser.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);

            signIn(page, verification);
            page.waitForURL(url -> url.startsWith(authServer.issuer() + "/oauth2/consent"));
            page.click(ALLOW);
            page.waitForURL(url -> url.contains("success"));

            final var summary = tool.await(COMPLETED, TOOL_TIMEOUT);
            assertTrue(summary.contains("token_type=Bearer"), summary);
            assertTrue(summary.contains("refresh_token=true"), summary);
            final var claims = claimsOf(tool.await(ACCESS_TOKEN, EXIT_TIMEOUT));
            assertEquals("demo", claims.get("sub").asString());
            assertTrue(claims.get("scope").toString().contains("documents.read"), claims.toString());
            assertEquals(SUCCESS, tool.awaitExit(EXIT_TIMEOUT));
        } finally {
            tool.stop();
        }
    }

    /**
     * Verifies that a user who denies the consent leaves the tool without tokens: it ends with an error.
     *
     * @throws Exception if the tool or the browser fails.
     */
    @Test
    void deviceFlow_whenTheUserDenies_theToolEndsWithoutTokens() throws Exception {
        final var tool = startTool();
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            tool.await(USER_CODE, TOOL_TIMEOUT);
            final var verification = tool.await(COMPLETE_URI, TOOL_TIMEOUT);
            final var page = browser.newPage();
            page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);

            signIn(page, verification);
            page.waitForURL(url -> url.startsWith(authServer.issuer() + "/oauth2/consent"));
            page.click(DENY);

            assertNotEquals(SUCCESS, tool.awaitExit(TOOL_TIMEOUT));
        } finally {
            tool.stop();
        }
    }

    /**
     * Starts the command line tool against the server and has it print the access token it obtains.
     *
     * @return the running tool.
     * @throws Exception if the process cannot be started.
     */
    private static ManagedApp startTool() throws Exception {
        return ManagedApp.start(RunningAuthServer.jar("serviceclient.jar"), List.of(
                "--spring.profiles.active=device-flow",
                "--device-flow.issuer=" + authServer.issuer(),
                "--device-flow.print-access-token=true"), List.of());
    }

    /**
     * Opens the verification address, which sends the browser to the login page, and signs the demo user in.
     *
     * @param page         the browser page.
     * @param verification the complete verification address.
     */
    private static void signIn(final Page page, final String verification) {
        page.navigate(verification);
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
        page.fill("#username", "demo");
        page.fill("#password", authServer.demoPassword());
        page.click("button[type=submit]");
    }

    /**
     * Reads the claims of a JWT without verifying it: the test only inspects what the server issued.
     *
     * @param jwt the compact serialization.
     * @return the claims.
     */
    private static JsonNode claimsOf(final String jwt) {
        return JSON.readTree(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[PAYLOAD]),
                StandardCharsets.UTF_8));
    }
}
