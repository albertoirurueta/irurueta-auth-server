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

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import tools.jackson.databind.JsonNode;

/**
 * Checks the whole sign-in with a password and an authenticator app code: the tokens say how the user
 * authenticated ({@code amr}, {@code acr}, {@code auth_time}), and a wrong code is refused.
 */
class TotpLoginIT extends AbstractMfaFlow {

    /** {@code amr} of a user who presented a password, a one-time password and so more than one factor. */
    private static final List<String> MFA_AMR = List.of("pwd", "otp", "mfa");

    /** Name of the claim with the authentication methods. */
    private static final String AMR = "amr";

    /** Name of the claim with the authentication context class. */
    private static final String ACR = "acr";

    /**
     * Verifies that, after the right code, the access token and the ID token carry the multi-factor claims.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenCodeIsRight_issuesTokensThatCarryAmrAndAcr() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        final var verifier = newVerifier();
        final var authorizeUri = signInForAuthorization(enrolled.user(), client, verifier, Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);

        final var posted = postSecondFactor(session, getTools().codeNow(enrolled.id(), 0), false, false);
        assertAccepted(posted);
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        final var id = AuthServerFixtures.claimsOf(tokens.get("id_token").asString());
        assertEquals(MFA_AMR, strings(access.get(AMR)));
        assertEquals(MFA_AMR, strings(id.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, id.get(ACR).asString());
        assertTrue(access.get("auth_time").isNumber(), "auth_time must be epoch seconds");
    }

    /**
     * Verifies that a user with a second factor who signs in to a client that does not require it still only
     * presents the password, and the tokens say so.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenNobodyRequiresMfa_issuesTokensWithPasswordClaims() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());

        final var tokens = getFixtures().authorizationCodeTokens(enrolled.user(), getFixtures().createCodeClient());

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(List.of("pwd"), strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.PASSWORD, access.get(ACR).asString());
    }

    /**
     * Verifies that a wrong code sends the user back to the page with an error and issues nothing.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenCodeIsWrong_redirectsBackWithAnError() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), session);

        final var posted = postSecondFactor(session, getTools().wrongCode(enrolled.id()), false, false);

        assertTrue(posted.getResponse().getRedirectedUrl().endsWith("/login/second-factor?error"));
        expectSecondFactorPage(authorizeUri, session);
    }

    /**
     * Reads the strings of a JSON array.
     *
     * @param array the array.
     * @return its elements.
     */
    private static List<String> strings(final JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).map(JsonNode::asString).toList();
    }
}
