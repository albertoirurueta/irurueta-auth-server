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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that a password alone is never enough when multi-factor authentication is required: by the client
 * ({@code mfa.required} setting) or by the user ({@code mfa_required} column). The browser is sent to the
 * second-factor page and no authorization code is issued.
 */
class MfaPasswordOnlyForcedIT extends AbstractMfaFlow {

    /** Path of the second-factor page. */
    private static final String SECOND_FACTOR_PAGE = "/login/second-factor";

    /**
     * Verifies that a client that requires MFA sends a password-only user to the second-factor page, which offers
     * the TOTP form, and keeps doing so.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenClientRequiresMfaAndOnlyPasswordWasPresented_redirectsToSecondFactorPage() throws Exception {
        final var user = getFixtures().createUser();
        final var client = getFixtures().createMfaCodeClient();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, client, newVerifier(), Map.of(), session);

        expectSecondFactorPage(authorizeUri, session);
        expectSecondFactorPage(authorizeUri, session);
        getMockMvc().perform(get(SECOND_FACTOR_PAGE).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("name=\"code\"")));
    }

    /**
     * Verifies that an account that requires MFA is sent to the second-factor page even when the client does not.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenUserRequiresMfaAndOnlyPasswordWasPresented_redirectsToSecondFactorPage() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var client = getFixtures().createCodeClient();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, client, newVerifier(), Map.of(), session);

        expectSecondFactorPage(authorizeUri, session);
    }

    /**
     * Verifies that, when nobody requires MFA, the password alone still obtains the code (the control of the tests
     * above).
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenNobodyRequiresMfa_issuesTheCodeAfterThePassword() throws Exception {
        final var user = getFixtures().createUser();
        final var client = getFixtures().createCodeClient();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(user, client, newVerifier(), Map.of(), session);

        final var redirect = getMockMvc().perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();

        assertTrue(redirect != null && redirect.startsWith(AuthServerFixtures.REDIRECT_URI + "?code="));
    }
}
