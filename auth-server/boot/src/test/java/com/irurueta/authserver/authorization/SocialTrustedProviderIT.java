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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Checks what trusting a provider for multi-factor authentication changes, against a fake Google configured with
 * {@code trust-mfa}: the provider's own multi-factor sign-in counts only when the ID token really reports {@code mfa}
 * in its {@code amr}, and then the user with an authenticator app is not asked for a code again and the tokens list
 * the upstream factors; a sign-in the provider did not vouch for as multi-factor still goes through the second-factor
 * step. Every client id and secret is generated at run time.
 */
class SocialTrustedProviderIT extends AbstractSocialFlow {

    /** Client id of Google, generated for the run. */
    private static final String GOOGLE_CLIENT_ID = "google-" + UUID.randomUUID();

    /** Issuer of the ID tokens of Google. */
    private static final String GOOGLE_ISSUER = "https://accounts.google.com";

    /** Name of the claim with the authentication methods the provider used. */
    private static final String UPSTREAM_AMR = "amr";

    /**
     * Configures Google as a provider trusted for multi-factor authentication.
     *
     * @param registry registry of the properties of the context.
     */
    @DynamicPropertySource
    static void providers(final DynamicPropertyRegistry registry) {
        registry.add("authserver.social.providers.google.client-id", () -> GOOGLE_CLIENT_ID);
        registry.add("authserver.social.providers.google.client-secret", () -> UUID.randomUUID().toString());
        registry.add("authserver.social.providers.google.trust-mfa", () -> "true");
    }

    /**
     * Verifies that a sign-in the trusted provider reports as multi-factor completes the authorization without the
     * second-factor step, and that the tokens show the upstream factors and the multi-factor class.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheTrustedProviderReportsMfa_skipsTheSecondFactorAndReportsTheUpstreamFactors()
            throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);
        final var claims = FakeIdentityProviders.userClaims(
                "subject-" + UUID.randomUUID(), enrolled.user().email(), true);
        claims.put(UPSTREAM_AMR, List.of("pwd", "mfa"));

        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID, claims);
        final var tokens = completeAuthorization(authorizeUri, client, verifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(List.of("fed", "mfa", "pwd"), strings(access.get(AMR)));
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
        assertEquals("google", access.get("idp").asString());
        assertEquals(enrolled.user().username(), access.get(SUB).asString());
    }

    /**
     * Verifies that the same strong sign-in also satisfies a step-up request for the multi-factor class: the
     * authorization endpoint applies the rule its tokens' {@code acr} comes from, so the user is not sent to the
     * second-factor page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheTrustedProviderReportsMfaAndStepUpIsRequested_issuesTheCodeWithoutSecondFactor()
            throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);
        final var claims = FakeIdentityProviders.userClaims(
                "subject-" + UUID.randomUUID(), enrolled.user().email(), true);
        claims.put(UPSTREAM_AMR, List.of("pwd", "mfa"));
        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID, claims);
        completeAuthorization(authorizeUri, client, verifier, session);

        final var stepUpVerifier = newVerifier();
        final var stepUpUri = AuthServerFixtures.authorizeUri(client, stepUpVerifier,
                Map.of("acr_values", AuthenticationContextClass.MULTI_FACTOR));
        final var tokens = completeAuthorization(stepUpUri, client, stepUpVerifier, session);

        final var access = AuthServerFixtures.claimsOf(tokens.get("access_token").asString());
        assertEquals(AuthenticationContextClass.MULTI_FACTOR, access.get(ACR).asString());
    }

    /**
     * Verifies that a trusted provider that does not report {@code mfa} is an ordinary primary factor: the user with
     * an authenticator app is still sent to the second-factor page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheTrustedProviderDoesNotReportMfa_asksForTheSecondFactor() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);
        final var claims = FakeIdentityProviders.userClaims(
                "subject-" + UUID.randomUUID(), enrolled.user().email(), true);
        claims.put(UPSTREAM_AMR, List.of("pwd"));

        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID, claims);

        expectSecondFactorPage(authorizeUri, session);
    }

    /**
     * Verifies that a trusted provider that sends no {@code amr} at all is an ordinary primary factor too.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheTrustedProviderSendsNoAmr_asksForTheSecondFactor() throws Exception {
        final var enrolled = getFixtures().createEnrolledUser(getTools());
        final var session = new MockHttpSession();
        final var client = getFixtures().createCodeClient();
        final var verifier = newVerifier();
        final var authorizeUri = beginAuthorization(client, verifier, session);

        signInWithOidc(session, "google", GOOGLE_ISSUER, GOOGLE_CLIENT_ID,
                FakeIdentityProviders.userClaims("subject-" + UUID.randomUUID(), enrolled.user().email(), true));

        expectSecondFactorPage(authorizeUri, session);
        final var redirect = getMockMvc().perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertNotNull(redirect);
        assertTrue(redirect.endsWith(SECOND_FACTOR_PAGE));
    }
}
