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

package com.irurueta.authserver.authorization;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Locale;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks the pages the passkeys add or extend, rendered through the real {@code PageRenderer} in English: the
 * passkey section of the login page and its script (which the content security policy must allow without a nonce),
 * the passkey action of the second-factor page and the account page that registers passkeys.
 */
class PasskeyPagesIT extends AbstractPasskeyFlow {

    /** Path of the login page. */
    private static final String LOGIN = "/login";

    /** Path of the script. */
    private static final String SCRIPT = "/js/passkeys.js";

    /** Matches a script element that has no {@code src}, that is, an inline script. */
    private static final Pattern INLINE_SCRIPT = Pattern.compile("<script(?![^>]*\\bsrc=)[^>]*>");

    /**
     * Pins the locale of the texts the tests assert on.
     */
    @BeforeEach
    void pinTheLocale() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
    }

    /**
     * Restores the locale.
     */
    @AfterEach
    void restoreTheLocale() {
        LocaleContextHolder.resetLocaleContext();
    }

    /**
     * Verifies that the login page offers the passkey: a field the browser fills with passkeys (conditional
     * mediation), a button, the CSRF header and token and the URLs of the WebAuthn endpoints for the script, and no
     * inline script, since the policy only allows same-origin resources.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void loginPage_whenRendered_offersPasskeysWithAnExternalScript() throws Exception {
        final var html = getMockMvc().perform(get(LOGIN))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")))
                .andExpect(content().string(containsString("autocomplete=\"username webauthn\"")))
                .andExpect(content().string(containsString("data-passkey-button")))
                .andExpect(content().string(containsString("Sign in with a passkey")))
                .andExpect(content().string(containsString("src=\"/js/passkeys.js\"")))
                .andExpect(content().string(containsString("data-csrf-header=\"X-CSRF-TOKEN\"")))
                .andExpect(content().string(containsString("data-csrf-token=\"")))
                .andExpect(content().string(containsString("data-options-url=\"/webauthn/authenticate/options\"")))
                .andExpect(content().string(containsString("data-login-url=\"/login/webauthn\"")))
                .andExpect(content().string(containsString("data-error-url=\"/login?error\"")))
                .andExpect(content().string(containsString("autocomplete=\"current-password\"")))
                .andReturn().getResponse().getContentAsString();

        assertEquals(false, INLINE_SCRIPT.matcher(html).find(), "The page must not carry an inline script");
    }

    /**
     * Verifies that the script is served to anybody (the login page needs it before sign-in) and reads the URLs of
     * the endpoints from the markup instead of hard-coding them.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void script_whenRequestedAnonymously_isServed() throws Exception {
        getMockMvc().perform(get(SCRIPT))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("container.dataset.optionsUrl")))
                .andExpect(content().string(containsString("container.dataset.loginUrl")))
                .andExpect(content().string(containsString("container.dataset.registerUrl")))
                .andExpect(content().string(not(containsString("\"/login/webauthn\""))))
                .andExpect(content().string(not(containsString("\"/webauthn/"))));
    }

    /**
     * Verifies that the second-factor page only offers a passkey to a user who has one.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactorPage_whenUserHasAPasskey_offersItAndOtherwiseDoesNot() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = signInWithThePasswordOnly(enrolled.user());
        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("data-passkey-button"))));

        seedPasskey(enrolled.user().username(), "Laptop");

        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("data-passkey-button")))
                .andExpect(content().string(containsString("Use a passkey")))
                .andExpect(content().string(containsString("data-error-url=\"/login/second-factor?error\"")))
                .andExpect(content().string(containsString("data-options-url=\"/webauthn/authenticate/options\"")))
                .andExpect(content().string(containsString("data-login-url=\"/login/webauthn\"")))
                .andExpect(content().string(containsString("name=\"code\"")));
    }

    /**
     * Verifies that a user whose only second factor is a passkey gets the passkey action on the second-factor page
     * and neither the enrolment of an authenticator app nor its code forms, and that no authenticator app secret is
     * generated for them by rendering the page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactorPage_whenThePasskeyIsTheOnlySecondFactor_offersItWithoutEnrollingAnAuthenticatorApp()
            throws Exception {
        final var user = getFixtures().createUser();
        seedPasskey(user.username(), "Laptop");
        final var session = signInWithThePasswordOnly(user);

        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("data-passkey-button")))
                .andExpect(content().string(not(containsString("totp-enrolment"))))
                .andExpect(content().string(not(containsString("otpauth://"))))
                .andExpect(content().string(not(containsString("/login/second-factor/totp"))));

        assertEquals(0L, getJdbc().sql("""
                        SELECT count(*) FROM totp_credentials t JOIN users u ON u.id = t.user_id
                        WHERE u.username = ?""").param(user.username()).query(Long.class).single(),
                "Rendering the page must not create an authenticator app secret");
    }

    /**
     * Verifies the account page: anonymous visitors are sent to sign in, a session that has not completed the second
     * factor is sent to the second-factor page, and a session that satisfies the policy sees its passkeys and the
     * registration helper (a name field of at most 100 characters and a button).
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void accountPage_whenRequested_isGuardedAndListsThePasskeysWithTheRegistrationHelper() throws Exception {
        getMockMvc().perform(get(ACCOUNT_PAGE))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));

        final var enrolled = getFixtures().createEnrolledUser(getTools());
        seedPasskey(enrolled.user().username(), "Laptop");
        final MockHttpSession pending = signInWithThePasswordOnly(enrolled.user());
        getMockMvc().perform(get(ACCOUNT_PAGE).session(pending))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login/second-factor"));

        final var session = signInCompletingTheSecondFactor(enrolled);
        getMockMvc().perform(get(ACCOUNT_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("<title>Passkeys</title>")))
                .andExpect(content().string(containsString("Your passkeys")))
                .andExpect(content().string(containsString("Laptop")))
                .andExpect(content().string(containsString("data-passkey-register")))
                .andExpect(content().string(containsString("data-passkey-label")))
                .andExpect(content().string(containsString("maxlength=\"100\"")))
                .andExpect(content().string(containsString("src=\"/js/passkeys.js\"")))
                .andExpect(content().string(containsString("data-csrf-header=\"X-CSRF-TOKEN\"")))
                .andExpect(content().string(containsString("data-options-url=\"/webauthn/register/options\"")))
                .andExpect(content().string(containsString("data-register-url=\"/webauthn/register\"")));
    }

    /**
     * Verifies that the account page of a user without passkeys says so.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void accountPage_whenUserHasNoPasskeys_saysSo() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();
        getFixtures().signIn(user, session);

        getMockMvc().perform(get(ACCOUNT_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("You have not registered a passkey yet.")));
    }
}
