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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks the numeric code sent by e-mail, read from Mailpit, as a primary sign-in and as a second factor: the tokens
 * say how the user authenticated, a code only works in the browser that asked for it, a code is spent when it is used
 * and a wrong code is refused. As a second factor the e-mail is offered, delivered and accepted only to a user without
 * any other confirmed second factor.
 */
class OttEmailCodeIT extends AbstractOttFlow {

    /** {@code amr} of a user who presented a password, an e-mail code and so more than one factor. */
    private static final List<String> MFA_AMR = List.of("pwd", "otp", "mfa");

    /** Where a failed code attempt is sent. */
    private static final String CODE_ERROR = "/login/ott?error";

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /**
     * Verifies that a user who asks for a code by e-mail and posts it signs in without a password, and that the
     * tokens carry {@code amr} {@code otp}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenCodeFromEmailIsPosted_signsInWithOtp() throws Exception {
        final var user = getFixtures().createUser();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = plainAuthorizeUri(client, verifier);
        getMockMvc().perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());

        requestToken(session, user.username(), "email", "code", "login");
        final var message = mailpit().awaitMessageTo(user.email());
        assertEquals("Your sign-in code", message.subject());
        final var sessionId = session.getId();
        assertAccepted(postToken(session, message.code()));
        assertNotEquals(sessionId, session.getId(), "The session id must change when the user signs in");
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(EMAIL_AMR, strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.PASSWORD, access.get(ACR).asString());
    }

    /**
     * Verifies that a user who must present a second factor, and who signed in with the password, can complete it with
     * a code sent by e-mail, and that the tokens then say password, one-time password and multi-factor.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenCodeFromEmailIsPosted_issuesTokensThatCarryMfa() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var verifier = newVerifier();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, client, verifier, Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);
        assertTrue(secondFactorPage(session).contains("E-mail me a code"));

        requestToken(session, user.username(), "email", "code", "second-factor");
        final var code = mailpit().awaitMessageTo(user.email()).code();
        final var sessionId = session.getId();
        assertAccepted(postSecondFactorCode(session, code));
        assertNotEquals(sessionId, session.getId(), "The session id must change with the second factor");
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(MFA_AMR, strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
    }

    /**
     * Verifies that a user with another confirmed second factor (an authenticator app) is neither offered nor sent an
     * e-mail code as the second factor, although the request is answered as any other.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenUserHasAnotherSecondFactor_sendsNoEmailCode() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var user = enrolled.user();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, getFixtures().createMfaCodeClient(), newVerifier(),
                Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);
        assertFalse(secondFactorPage(session).contains("E-mail me a code"));

        requestToken(session, user.username(), "email", "code", "second-factor");

        assertEquals(0, mailpit().countMessagesTo(user.email()));
    }

    /**
     * Verifies that an e-mail code delivered while the user had no other second factor is refused once the user has
     * confirmed one: the rule is enforced when the code is presented, not only when it is offered.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenUserConfirmedAnotherSecondFactorMeanwhile_refusesTheEmailCode() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var session = new MockHttpSession();
        signInForAuthorization(user, getFixtures().createMfaCodeClient(), newVerifier(), Map.of(), session);
        requestToken(session, user.username(), "email", "code", "second-factor");
        final var code = mailpit().awaitMessageTo(user.email()).code();
        final var tools = getTools();
        final var userId = userAccounts.findByUsername(user.username()).orElseThrow().id();
        tools.credentials().save(new TotpCredential(userId, tools.cipher().encrypt(tools.secrets().generate()), true,
                TotpCredential.NEVER_USED, Instant.now()));

        final var refused = postSecondFactorCode(session, code);

        assertTrue(refused.getResponse().getRedirectedUrl().contains("error"),
                "The code must be refused: " + refused.getResponse().getRedirectedUrl());
    }

    /**
     * Verifies that a wrong code sends the user back to the code page with an error and signs nobody in, and that the
     * right code still works afterwards.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenCodeIsWrong_redirectsBackWithAnError() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();
        requestToken(session, user.username(), "email", "code", "login");
        final var code = mailpit().awaitMessageTo(user.email()).code();

        final var wrong = postToken(session, wrongCodeLike(code));

        assertTrue(wrong.getResponse().getRedirectedUrl().endsWith(CODE_ERROR));
        assertAccepted(postToken(session, code));
    }

    /**
     * Verifies that a code only works in the browser that asked for it: another browser that types it is refused,
     * while the browser that asked still can use it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenCodeIsPostedFromAnotherBrowser_isRefused() throws Exception {
        final var user = getFixtures().createUser();
        final var asking = new MockHttpSession();
        requestToken(asking, user.username(), "email", "code", "login");
        final var code = mailpit().awaitMessageTo(user.email()).code();

        final var other = postToken(new MockHttpSession(), code);

        assertNotNull(other.getResponse().getRedirectedUrl());
        assertTrue(other.getResponse().getRedirectedUrl().contains("error"));
        assertAccepted(postToken(asking, code));
    }

    /**
     * Verifies that a code is spent when it is used: posting it again, in a new request of the same browser, is
     * refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenCodeIsUsedTwice_theSecondUseIsRefused() throws Exception {
        final var user = getFixtures().createUser();
        final var session = new MockHttpSession();
        requestToken(session, user.username(), "email", "code", "login");
        final var code = mailpit().awaitMessageTo(user.email()).code();
        assertAccepted(postToken(session, code));

        final var again = postToken(session, code);

        assertNotNull(again.getResponse().getRedirectedUrl());
        assertTrue(again.getResponse().getRedirectedUrl().contains("error"));
    }
}
