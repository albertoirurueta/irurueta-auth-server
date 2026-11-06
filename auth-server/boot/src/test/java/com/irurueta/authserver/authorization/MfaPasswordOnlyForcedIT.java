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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.totp.RecoveryCodesPageController;
import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

/**
 * Checks that a password alone is never enough when multi-factor authentication is required: by the client
 * ({@code mfa.required} setting), by the user ({@code mfa_required} column) or because the user enrolled a second
 * factor. The browser is sent to the second-factor page and no authorization code is issued; a user who has no
 * second factor yet enrols one there, sees the recovery codes once and resumes the sign-in.
 */
class MfaPasswordOnlyForcedIT extends AbstractMfaFlow {

    /** Marker of the enrolment form in the second-factor page. */
    private static final String ENROL_FIELD = "name=\"enroll\"";

    /** Port that stores the recovery codes. */
    @Autowired
    private RecoveryCodeRepository recoveryCodes;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

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
     * Verifies that a user who enrolled an authenticator app is always asked for it, even when neither the client nor
     * an administrator requires it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenUserHasAConfirmedSecondFactor_redirectsToSecondFactorPage() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var client = getFixtures().createCodeClient();
        final var session = new MockHttpSession();
        final var authorizeUri = signInForAuthorization(enrolled.user(), client, newVerifier(), Map.of(), session);

        expectSecondFactorPage(authorizeUri, session);
        final var page = secondFactorPage(session);
        assertTrue(page.contains("name=\"code\""));
        assertFalse(page.contains(ENROL_FIELD), "An enrolled user must not be offered a new enrolment");
    }

    // tag::mfa-enrolment-in-login-it[]
    /**
     * Verifies that a user who must use a second factor but has none enrols an authenticator app on the second-factor
     * page, sees the recovery codes exactly once and then resumes the authorization request, whose tokens report the
     * second factor.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void secondFactor_whenUserMustEnrol_enrolsShowsTheRecoveryCodesOnceAndResumes() throws Exception {
        final var user = getFixtures().createUser();
        getFixtures().requireMfa(user, getTools());
        final var userId = userAccounts.findByUsername(user.username()).orElseThrow().id();
        final var client = getFixtures().createCodeClient();
        final var session = new MockHttpSession();
        final var verifier = newVerifier();
        final var authorizeUri = signInForAuthorization(user, client, verifier, Map.of(), session);
        expectSecondFactorPage(authorizeUri, session);

        final var page = secondFactorPage(session);
        assertTrue(page.contains(ENROL_FIELD) && page.contains("otpauth://totp/")
                && page.contains("src=\"data:image/png;base64,"), "The page must offer the enrolment");

        final var enrolled = postEnrolment(session, getTools().codeNow(userId, 0));
        assertEquals(RecoveryCodesPageController.RECOVERY_CODES_PATH, enrolled.getResponse().getRedirectedUrl());

        final var codesPage = getMockMvc().perform(get(RecoveryCodesPageController.RECOVERY_CODES_PATH)
                .session(session)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT, recoveryCodes.findUnused(userId).size());
        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT, codesPage.split("<li><code>", -1).length - 1);
        assertTrue(codesPage.contains("/oauth2/authorize?"), "The Continue link must resume the authorization");
        getMockMvc().perform(get(RecoveryCodesPageController.RECOVERY_CODES_PATH).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("<li><code>"))));

        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);
        assertEquals(AuthenticationContextClass.MULTI_FACTOR,
                AuthServerFixtures.claimsOf(tokens.get("access_token").asString()).get(ACR).asString());
    }
    // end::mfa-enrolment-in-login-it[]

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
