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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks the magic link sent by e-mail, read from Mailpit, as a primary sign-in and as a second factor: opening the
 * link only shows a page (a mail scanner that follows it does not spend it), the button's post signs the user in, a
 * link is spent when it is used, a link can be opened in another browser to sign in but not to confirm a second
 * factor.
 */
class OttMagicLinkIT extends AbstractOttFlow {

    /** {@code amr} of a user who presented a password, a magic link and so more than one factor. */
    private static final List<String> MFA_AMR = List.of("pwd", "otp", "mfa");

    /** Path of the page of the phone, which only a signed-in user may open. */
    private static final String SIGNED_IN_PAGE = "/account/phone";

    /**
     * Verifies that a user who asks for a link signs in with it, that the link only shows the confirmation page when
     * it is opened (twice, as a scanner would) and that the button's post signs the user in with {@code amr}
     * {@code otp}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenLinkIsOpenedAndConfirmed_signsInWithOtp() throws Exception {
        final var user = getFixtures().createUser();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = plainAuthorizeUri(client, verifier);
        getMockMvc().perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());

        requestToken(session, user.username(), "email", "link", "login");
        final var message = mailpit().awaitMessageTo(user.email());
        assertEquals("Your sign-in link", message.subject());
        final var token = message.linkToken();
        for (var scan = 0; scan < 2; scan++) {
            getMockMvc().perform(get(CONFIRM).param(TOKEN_FIELD, token))
                    .andExpect(status().isOk())
                    .andExpect(content().string(containsString("name=\"token\" value=\"" + token + "\"")));
        }
        assertAccepted(postToken(session, token));
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(EMAIL_AMR, strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.PASSWORD, access.get(ACR).asString());
    }

    /**
     * Verifies that a user who must present a second factor, and who signed in with the password, completes it with a
     * link opened in the same browser, and that the tokens say password, one-time password and multi-factor.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenLinkIsConfirmedInTheSameBrowser_issuesTokensThatCarryMfa() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, client, verifier, Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);
        assertTrue(secondFactorPage(session).contains("E-mail me a link"));

        requestToken(session, user.username(), "email", "link", "second-factor");
        final var token = mailpit().awaitMessageTo(user.email()).linkToken();
        getMockMvc().perform(get(CONFIRM).param(TOKEN_FIELD, token).session(session)).andExpect(status().isOk());
        assertAccepted(postToken(session, token));
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(MFA_AMR, strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
    }

    /**
     * Verifies that a link is spent when it is used: posting it a second time is refused and sends the user to the
     * login page with an error.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenLinkIsUsedTwice_theSecondUseIsRefused() throws Exception {
        final var user = getFixtures().createUser();
        requestToken(new MockHttpSession(), user.username(), "email", "link", "login");
        final var token = mailpit().awaitMessageTo(user.email()).linkToken();
        assertAccepted(postToken(new MockHttpSession(), token));

        final var again = postToken(new MockHttpSession(), token);

        assertNotNull(again.getResponse().getRedirectedUrl());
        assertTrue(again.getResponse().getRedirectedUrl().endsWith("/login?error"));
    }

    /**
     * Verifies that a link that signs in can be confirmed in another browser than the one that asked for it, as when
     * the user opens the mail on another device.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenLinkIsConfirmedInAnotherBrowser_signsThatBrowserIn() throws Exception {
        final var user = getFixtures().createUser();
        requestToken(new MockHttpSession(), user.username(), "email", "link", "login");
        final var token = mailpit().awaitMessageTo(user.email()).linkToken();
        final var other = new MockHttpSession();

        assertAccepted(postToken(other, token));

        getMockMvc().perform(get(SIGNED_IN_PAGE).session(other)).andExpect(status().isOk());
    }

    /**
     * Verifies that a user with another confirmed second factor (an authenticator app) is neither offered nor sent a
     * magic link as the second factor, although the request is answered as any other.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenUserHasAnotherSecondFactor_sendsNoLink() throws Exception {
        final var user = getFixtures().createEnrolledUser(getTools()).user();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, getFixtures().createMfaCodeClient(), newVerifier(),
                Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);
        assertFalse(secondFactorPage(session).contains("E-mail me a link"));

        requestToken(session, user.username(), "email", "link", "second-factor");

        assertEquals(0, mailpit().countMessagesTo(user.email()));
    }

    /**
     * Verifies that a link sent for a second factor is refused when it is confirmed in a browser that did not present
     * a primary factor.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenLinkIsConfirmedInAnotherBrowser_isRefused() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        signInForAuthorization(user, client, newVerifier(), Map.of(), session);
        requestToken(session, user.username(), "email", "link", "second-factor");
        final var token = mailpit().awaitMessageTo(user.email()).linkToken();
        final var other = new MockHttpSession();

        final var refused = postToken(other, token);

        assertNotNull(refused.getResponse().getRedirectedUrl());
        assertTrue(refused.getResponse().getRedirectedUrl().contains("error"));
        getMockMvc().perform(get(SIGNED_IN_PAGE).session(other)).andExpect(status().is3xxRedirection());
    }
}
