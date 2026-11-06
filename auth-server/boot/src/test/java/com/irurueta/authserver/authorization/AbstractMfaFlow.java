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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredEntryPoint;
import com.irurueta.authserver.authorization.api.web.totp.TotpAuthenticationFilter;
import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.mfa.UserMfaSettingsRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.totp.SecretGenerator;
import com.irurueta.authserver.authorization.domain.totp.TotpAlgorithm;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import lombok.AccessLevel;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.JsonNode;

/**
 * Shared set-up of the multi-factor integration tests: the application with a real database, the fixtures (users with
 * an enrolled authenticator app, clients that require a second factor) and the steps of the browser flow (authorize,
 * sign in, post a second factor, resume). Every secret is generated at runtime.
 */
@PostgresIT
@AutoConfigureMockMvc
abstract class AbstractMfaFlow {

    /** Name of the cookie that remembers a trusted device. */
    static final String TRUSTED_DEVICE_COOKIE = "__Host-TRUSTED-DEVICE";

    /** MockMvc bound to the application context. */
    @Autowired
    @Getter(AccessLevel.PROTECTED)
    private MockMvc mockMvc;

    /** Fixtures of the test. */
    @Getter(AccessLevel.PROTECTED)
    private AuthServerFixtures fixtures;

    /** Collaborators that enrol an authenticator app and compute its codes. */
    @Getter(AccessLevel.PROTECTED)
    private AuthServerFixtures.TotpTools tools;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores the authenticator app credentials. */
    @Autowired
    private TotpCredentialRepository totpCredentials;

    /** Cipher of the stored secrets. */
    @Autowired
    private TotpSecretCipher totpSecretCipher;

    /** Generator of secrets. */
    @Autowired
    private SecretGenerator secretGenerator;

    /** The TOTP algorithm of the application. */
    @Autowired
    private TotpAlgorithm totpAlgorithm;

    /** Use case that generates recovery codes. */
    @Autowired
    private GenerateRecoveryCodesUseCase generateRecoveryCodesUseCase;

    /** Port that stores the per-user multi-factor settings. */
    @Autowired
    private UserMfaSettingsRepository userMfaSettings;

    /** Creates the fixtures. */
    @BeforeEach
    void setUpFixtures() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
        tools = new AuthServerFixtures.TotpTools(totpCredentials, totpSecretCipher, secretGenerator, totpAlgorithm,
                generateRecoveryCodesUseCase, userMfaSettings);
    }

    /**
     * Starts an authorization request and signs the user in with the password, leaving the browser session signed in
     * with one factor.
     *
     * @param user     the user.
     * @param client   the client that requests the code.
     * @param verifier PKCE code verifier.
     * @param extra    additional authorization parameters.
     * @param session  the browser session.
     * @return the URI of the authorization request.
     * @throws Exception if a request cannot be performed.
     */
    protected String signInForAuthorization(final AuthServerFixtures.TestUser user,
            final AuthServerFixtures.TestClient client, final String verifier, final Map<String, String> extra,
            final MockHttpSession session) throws Exception {
        final var authorizeUri = AuthServerFixtures.authorizeUri(client, verifier, extra);
        mockMvc.perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());
        fixtures.signIn(user, session);
        return authorizeUri;
    }

    /**
     * Requests the authorization endpoint and expects a redirect to the second-factor page.
     *
     * @param authorizeUri the authorization request.
     * @param session      the browser session.
     * @throws Exception if the request cannot be performed.
     */
    protected void expectSecondFactorPage(final String authorizeUri, final MockHttpSession session) throws Exception {
        final var redirect = mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
        assertTrue(redirect != null && redirect.endsWith(SecondFactorRequiredEntryPoint.SECOND_FACTOR_PATH),
                "Expected a redirect to the second-factor page but got " + redirect);
    }

    /**
     * Posts the TOTP or recovery-code form.
     *
     * @param session  the browser session.
     * @param code     the code typed by the user.
     * @param recovery whether it is a recovery code.
     * @param remember whether the user asks to remember the device.
     * @return the answer of the filter.
     * @throws Exception if the request cannot be performed.
     */
    protected MvcResult postSecondFactor(final MockHttpSession session, final String code, final boolean recovery,
            final boolean remember) throws Exception {
        final var request = post(TotpAuthenticationFilter.TOTP_PATH).session(session).with(csrf())
                .param(TotpAuthenticationFilter.CODE_PARAMETER, code);
        if (recovery) {
            request.param(TotpAuthenticationFilter.RECOVERY_PARAMETER, "true");
        }
        if (remember) {
            request.param(TotpAuthenticationFilter.REMEMBER_PARAMETER, "on");
        }
        return mockMvc.perform(request).andReturn();
    }

    /**
     * Fails unless a second-factor post was accepted, that is, redirected somewhere other than back with an error.
     *
     * @param posted the answer of the filter.
     */
    protected static void assertAccepted(final MvcResult posted) {
        final var redirect = posted.getResponse().getRedirectedUrl();
        assertTrue(redirect != null && !redirect.contains("error"), "The code was not accepted: " + redirect);
    }

    /**
     * Resumes the authorization request after the second factor and exchanges the code for the tokens.
     *
     * @param authorizeUri the authorization request.
     * @param client       the client that requests the tokens.
     * @param verifier     PKCE code verifier.
     * @param session      the browser session.
     * @return the token endpoint answer.
     * @throws Exception if a request cannot be performed.
     */
    protected JsonNode completeAuthorization(final String authorizeUri, final AuthServerFixtures.TestClient client,
            final String verifier, final MockHttpSession session) throws Exception {
        final var authorized = mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn();
        return fixtures.exchangeCode(client, AuthServerFixtures.codeOf(authorized), verifier);
    }

    /**
     * Generates a PKCE verifier.
     *
     * @return the verifier.
     */
    protected static String newVerifier() {
        return AuthServerFixtures.randomValue() + AuthServerFixtures.randomValue();
    }

    /**
     * Computes the authorization URI of a request without extra parameters.
     *
     * @param client   the client.
     * @param verifier PKCE code verifier.
     * @return the authorization URI.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    protected static String plainAuthorizeUri(final AuthServerFixtures.TestClient client, final String verifier)
            throws NoSuchAlgorithmException {
        return AuthServerFixtures.authorizeUri(client, verifier, Map.of());
    }
}
