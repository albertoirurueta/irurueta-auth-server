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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks the OpenID Connect step-up parameters of the authorization endpoint: {@code acr_values} asks for a second
 * factor the session has not presented and {@code max_age} forces a new sign-in when the last one is too old.
 */
class StepUpIT extends AbstractMfaFlow {

    /** Time to let pass so a {@code max_age} of zero is exceeded, in milliseconds. */
    private static final long AGE_MILLIS = 1_100L;

    /** A {@code max_age} that a fresh sign-in satisfies, in seconds. */
    private static final String LONG_MAX_AGE = "300";

    /**
     * Verifies that asking for the multi-factor class sends a password-only session to the second-factor page and
     * that, once the code is posted, the tokens carry that class.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenAcrValuesAskForMfa_requiresTheSecondFactor() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createCodeClient();
        final var session = new MockHttpSession();
        final var verifier = newVerifier();
        final var authorizeUri = signInForAuthorization(enrolled.user(), client, verifier,
                Map.of("acr_values", AuthenticationContextClass.MULTI_FACTOR), session);

        expectSecondFactorPage(authorizeUri, session);
        final var posted = postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false);
        assertAccepted(posted);
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        assertEquals(AuthenticationContextClass.MULTI_FACTOR,
                AuthServerFixtures.claimsOf(tokens.get("access_token").asString()).get("acr").asString());
    }

    /**
     * Verifies that a request for the password class is satisfied by a password-only session of a user without a
     * second factor (one with a second factor is always asked for it).
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenAcrValuesAskForPassword_isSatisfiedByThePassword() throws Exception {
        final var user = getFixtures().createUser();
        final var client = getFixtures().createCodeClient();
        final var session = new MockHttpSession();
        final var verifier = newVerifier();
        final var authorizeUri = signInForAuthorization(user, client, verifier,
                Map.of("acr_values", AuthenticationContextClass.PASSWORD), session);

        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        assertEquals(AuthenticationContextClass.PASSWORD,
                AuthServerFixtures.claimsOf(tokens.get("access_token").asString()).get("acr").asString());
    }

    /**
     * Verifies that a session older than {@code max_age} is sent to sign in again, and that the new sign-in carries
     * a newer {@code auth_time}.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenMaxAgeIsExceeded_requiresANewSignIn() throws Exception {
        final var user = getFixtures().createUser();
        final var client = getFixtures().createCodeClient();
        final var session = new MockHttpSession();
        final var verifier = newVerifier();
        final var tooOld = signInForAuthorization(user, client, verifier, Map.of("max_age", "0"), session);
        TimeUnit.MILLISECONDS.sleep(AGE_MILLIS);
        final var reauthenticatedAfter = Instant.now().getEpochSecond();

        final var redirect = mockMvcRedirect(tooOld, session);
        assertTrue(redirect.endsWith("/login"), "Expected a redirect to the login page but got " + redirect);

        final var fresh = AuthServerFixtures.authorizeUri(client, verifier, Map.of("max_age", LONG_MAX_AGE));
        getFixtures().signIn(user, session);
        final var tokens = completeAuthorization(fresh, client, verifier, session);
        final var authTime = AuthServerFixtures.claimsOf(tokens.get("access_token").asString())
                .get("auth_time").asLong();
        assertTrue(authTime >= reauthenticatedAfter, "auth_time must be that of the new sign-in");
    }

    /**
     * Requests the authorization endpoint and answers where it redirects.
     *
     * @param authorizeUri the authorization request.
     * @param session      the browser session.
     * @return the redirect location.
     * @throws Exception if the request cannot be performed.
     */
    private String mockMvcRedirect(final String authorizeUri, final MockHttpSession session) throws Exception {
        return getMockMvc().perform(get(authorizeUri).session(session))
                .andReturn().getResponse().getRedirectedUrl();
    }
}
