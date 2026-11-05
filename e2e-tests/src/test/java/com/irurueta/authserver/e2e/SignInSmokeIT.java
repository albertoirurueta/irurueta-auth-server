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
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Playwright;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Smoke test of the whole sign-in flow: the packaged {@code auth-server} (dev profile, so the demo user and the
 * {@code bff} client are seeded with generated secrets) and {@code bff} are started on random ports against a
 * PostgreSQL container, and the demo user signs in through the BFF in headless Chromium.
 */
class SignInSmokeIT {

    /**
     * Matches the log line printed once the BFF is up.
     */
    private static final Pattern BFF_STARTED = Pattern.compile("Started BffApplication in");

    /**
     * Cookies are shared between ports of the same host, so the BFF is reached through a different host name than
     * the authorization server (which is {@code localhost}) to keep their {@code JSESSIONID} cookies apart.
     */
    private static final String BFF_HOST = "127.0.0.1";

    /**
     * HTTP status of a successful response.
     */
    private static final int HTTP_OK = 200;

    /**
     * The packaged authorization server and its database.
     */
    private static RunningAuthServer authServer;

    /**
     * The packaged backend-for-frontend.
     */
    private static ManagedApp bff;

    /**
     * Port of the BFF.
     */
    private static int bffPort;

    /**
     * Starts the database and both applications, and points the seeded {@code bff} client at the BFF's port.
     *
     * @throws Exception if an application or the container cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        bffPort = RunningAuthServer.freePort();
        authServer = RunningAuthServer.start();

        // the dev client is registered for http://localhost:8080; point it at the random BFF port instead
        authServer.sql("UPDATE oauth2_registered_client SET redirect_uris = 'http://" + BFF_HOST + ":" + bffPort
                + "/login/oauth2/code/bff' WHERE client_id = 'bff'");

        bff = ManagedApp.start(RunningAuthServer.jar("bff.jar"), List.of("--server.port=" + bffPort),
                List.of("AUTH_ISSUER=" + authServer.issuer(), "BFF_CLIENT_SECRET=" + authServer.clientSecret()));
        bff.await(BFF_STARTED, RunningAuthServer.STARTUP_TIMEOUT);
    }

    /**
     * Stops both applications and the database.
     */
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
     * Signs the demo user in through the BFF and reads the BFF's user endpoint.
     */
    @Test
    void bffUser_whenDemoUserSignsIn_containsSubject() {
        try (var playwright = Playwright.create(); var browser = launch(playwright)) {
            final var page = browser.newPage();
            page.navigate("http://" + BFF_HOST + ":" + bffPort + "/oauth2/authorization/bff");

            page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
            page.fill("#username", "demo");
            page.fill("#password", authServer.demoPassword());
            page.click("button[type=submit]");
            page.waitForURL(url -> url.startsWith("http://" + BFF_HOST + ":" + bffPort));

            final var response = page.navigate("http://" + BFF_HOST + ":" + bffPort + "/bff/user");
            assertEquals(HTTP_OK, response.status());
            assertTrue(response.text().contains("\"subject\":\"demo\""));
        }
    }

    /**
     * Launches headless Chromium.
     *
     * @param playwright the Playwright instance.
     * @return the browser.
     */
    private static Browser launch(final Playwright playwright) {
        return playwright.chromium().launch();
    }
}
