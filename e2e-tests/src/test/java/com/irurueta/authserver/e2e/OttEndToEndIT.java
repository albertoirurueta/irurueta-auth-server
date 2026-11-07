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

import com.irurueta.authserver.testsupport.Mailpit;
import com.irurueta.authserver.testsupport.MailpitClient;
import com.microsoft.playwright.Browser;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import java.security.SecureRandom;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;

/**
 * End-to-end test of the one-time tokens with a real browser: the packaged {@code auth-server} (dev profile) runs on
 * a random port against PostgreSQL and a Mailpit container that receives its e-mail. Headless Chromium visits a page
 * that needs a session, is sent to the login page and signs in with the code the e-mail carries, which the test reads
 * from the Mailpit HTTP API; in another scenario it signs in with the magic link, which a mail scanner can fetch
 * (twice) without spending it; in the last one a signed-in user enrols a phone with the code of the SMS the logging
 * sender recorded in the development inbox. Each scenario has a user of its own, copied from the demo user.
 */
class OttEndToEndIT {

    /** Longest wait for a page transition, in milliseconds. */
    private static final double PAGE_TIMEOUT_MILLIS = 30_000;

    /** HTTP status of a successful response. */
    private static final int HTTP_OK = 200;

    /** Path of the phone page, which needs a session. */
    private static final String PHONE_PATH = "/account/phone";

    /** Path of the second-factor page. */
    private static final String SECOND_FACTOR_PATH = "/login/second-factor";

    /** Path of the page where a code is typed. */
    private static final String CODE_PATH = "/login/ott";

    /** Path of the development SMS inbox. */
    private static final String INBOX_PATH = "/dev/sms-inbox";

    /** Selector of the button of the one-time token form of the login page. */
    private static final String SEND_BUTTON = "form.ott-login button[type=submit]";

    /** Selector of the submit button of the page the browser lands on to type a code or confirm a link. */
    private static final String SUBMIT_BUTTON = "main form button[type=submit]";

    /** Matches the code of the verification SMS in the HTML of the inbox. */
    private static final Pattern SMS_CODE = Pattern.compile("Your verification code is ([0-9]+)");

    /** Number of digits of the national number of a generated Spanish mobile phone. */
    private static final int PHONE_DIGITS = 8;

    /** Number of values of a decimal digit. */
    private static final int DECIMAL = 10;

    /** The Mailpit container. */
    private static GenericContainer<?> mailpit;

    /** Reads the e-mail the server sent. */
    private static MailpitClient mail;

    /** The packaged authorization server and its database. */
    private static RunningAuthServer authServer;

    /**
     * Starts Mailpit and the authorization server, whose mail sender points at it.
     *
     * @throws Exception if the containers or the server cannot be started.
     */
    @BeforeAll
    static void startApplications() throws Exception {
        mailpit = Mailpit.newContainer();
        mailpit.start();
        mail = Mailpit.clientOf(mailpit);
        authServer = RunningAuthServer.start(List.of(
                "--spring.mail.host=" + mailpit.getHost(),
                "--spring.mail.port=" + mailpit.getMappedPort(Mailpit.SMTP_PORT)));
    }

    /** Stops the server and the containers. */
    @AfterAll
    static void stopApplications() {
        if (authServer != null) {
            authServer.close();
        }
        if (mailpit != null) {
            mailpit.stop();
        }
    }

    /**
     * Signs a user in with the code of an e-mail: the browser is sent to the login page by the page it asked for,
     * asks for a code, types the one Mailpit received and lands on the page it originally asked for.
     *
     * @throws Exception if the user cannot be created.
     */
    @Test
    void signIn_whenCodeFromEmailIsTyped_landsOnTheRequestedPage() throws Exception {
        final var user = newUser();
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            final var page = newPage(browser);

            signInWithCode(page, user);

            assertTrue(page.textContent("h1").contains("Your phone"), page.url());
        }
    }

    /**
     * Signs a user in with the magic link of an e-mail: a scanner that fetches the link (twice) only gets the page that
     * asks for a confirmation, and the browser that confirms signs in and lands on the page it asked for.
     *
     * @throws Exception if the user cannot be created.
     */
    @Test
    void signIn_whenMagicLinkIsConfirmed_aScannerFetchDoesNotSpendIt() throws Exception {
        final var user = newUser();
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            final var page = newPage(browser);
            requestToken(page, user, "link");
            final var link = mail.awaitMessageTo(user + "@example.com").link();

            final var scanner = playwright.request().newContext();
            for (var scan = 0; scan < 2; scan++) {
                final var response = scanner.get(link);
                assertEquals(HTTP_OK, response.status());
                assertTrue(response.text().contains("Continue"));
            }
            page.navigate(link);
            page.click(SUBMIT_BUTTON);
            page.waitForURL(url -> url.startsWith(authServer.issuer() + PHONE_PATH));

            assertTrue(page.textContent("h1").contains("Your phone"), page.url());
        }
    }

    /**
     * Enrols a phone: a signed-in user types a number, reads the code of the verification SMS in the development inbox,
     * types it, and is then asked for a second factor because the verified phone makes it required: the page offers the
     * code by SMS, and the database holds the phone.
     *
     * @throws Exception if the user cannot be created or the database cannot be read.
     */
    @Test
    void phoneEnrolment_whenCodeFromDevInboxIsTyped_verifiesThePhone() throws Exception {
        final var user = newUser();
        final var national = nationalNumber();
        try (var playwright = Playwright.create(); var browser = playwright.chromium().launch()) {
            final var page = newPage(browser);
            signInWithCode(page, user);

            page.fill("#phone-number", "+34 6" + national);
            page.click("section.phone-enrol form[action$='/account/phone'] button[type=submit]");
            page.waitForURL(url -> url.contains("status=pending"));
            final var inbox = playwright.request().newContext().get(authServer.issuer() + INBOX_PATH).text();
            final var code = lastCodeOf(inbox, "+346" + national);
            page.fill("#phone-code", code);
            page.click("section.phone-enrol form[action$='/verify'] button[type=submit]");
            // the phone is now a confirmed second factor, so a session with only the e-mail code is asked for one
            page.waitForURL(url -> url.equals(authServer.issuer() + SECOND_FACTOR_PATH));

            assertTrue(page.textContent("main").contains("Send me a code by SMS"));
            assertEquals(List.of("1"), authServer.query("SELECT count(*) FROM user_phones WHERE phone_e164 = '+346"
                    + national + "'"));
        }
    }

    /**
     * Creates a user that is a copy of the demo user, under a name of its own.
     *
     * @return the name of the user, which is also the local part of its e-mail address.
     * @throws Exception if the user cannot be created.
     */
    private static String newUser() throws Exception {
        final var username = "ott-" + UUID.randomUUID().toString().substring(0, 8);
        authServer.createUserLikeDemo(username);
        return username;
    }

    /**
     * Opens a page in a browser with a timeout suited to the packaged application.
     *
     * @param browser the browser.
     * @return the page.
     */
    private static Page newPage(final Browser browser) {
        final var page = browser.newPage();
        page.setDefaultTimeout(PAGE_TIMEOUT_MILLIS);
        return page;
    }

    /**
     * Visits the phone page, which needs a session, and asks for a token on the login page it is sent to.
     *
     * @param page the page.
     * @param user the name of the user.
     * @param kind {@code code} or {@code link}.
     */
    private static void requestToken(final Page page, final String user, final String kind) {
        page.navigate(authServer.issuer() + PHONE_PATH);
        page.waitForURL(url -> url.startsWith(authServer.issuer() + "/login"));
        page.fill("#ott-username", user);
        page.check("form.ott-login input[name=kind][value=" + kind + "]");
        page.click(SEND_BUTTON);
        page.waitForURL(url -> url.equals(authServer.issuer() + CODE_PATH));
    }

    /**
     * Signs in with the code the e-mail carries and waits for the page the browser originally asked for.
     *
     * @param page the page.
     * @param user the name of the user.
     */
    private static void signInWithCode(final Page page, final String user) {
        requestToken(page, user, "code");
        page.fill("#ott-code", mail.awaitMessageTo(user + "@example.com").code());
        page.click(SUBMIT_BUTTON);
        page.waitForURL(url -> url.startsWith(authServer.issuer() + PHONE_PATH));
    }

    /**
     * Reads the code of the last verification SMS sent to a number from the HTML of the development inbox.
     *
     * @param inbox HTML of the inbox.
     * @param phone number the message was sent to, in E.164 form.
     * @return the digits of the code.
     */
    private static String lastCodeOf(final String inbox, final String phone) {
        String code = null;
        for (final var row : inbox.split("<tr")) {
            if (row.contains(phone)) {
                final var matcher = SMS_CODE.matcher(row);
                if (matcher.find()) {
                    code = matcher.group(1);
                }
            }
        }
        assertTrue(code != null, "The inbox holds no verification code for the number: " + inbox);
        return code;
    }

    /**
     * Generates the digits that follow the {@code 6} of a Spanish mobile number.
     *
     * @return the digits.
     */
    private static String nationalNumber() {
        final var random = new SecureRandom();
        final var builder = new StringBuilder();
        for (var i = 0; i < PHONE_DIGITS; i++) {
            builder.append(random.nextInt(DECIMAL));
        }
        return builder.toString();
    }
}
