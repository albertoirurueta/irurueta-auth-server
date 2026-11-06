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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.IsUserMfaRequiredUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.FactorAuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Unit tests of {@link MfaAuthorizationManager}.
 */
@ExtendWith(MockitoExtension.class)
class MfaAuthorizationManagerTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Identifier of the client used by the tests. */
    private static final String CLIENT_ID = "client";

    /** TOTP authority. */
    private static final String TOTP_AUTHORITY = "FACTOR_TOTP";

    /** Real policy. */
    @Spy
    private MfaPolicy mfaPolicy = new MfaPolicy();

    /** Registry of the known factors. */
    @Spy
    private AuthenticationFactorRegistry factorRegistry = new AuthenticationFactorRegistry(List.of(
            new AuthenticationFactor("password", "pwd", FactorGrantedAuthority.PASSWORD_AUTHORITY,
                    FactorStrength.PRIMARY),
            new AuthenticationFactor("totp", "otp", TOTP_AUTHORITY, FactorStrength.SECOND)));

    /** Tells whether a user requires MFA. */
    @Mock
    private IsUserMfaRequiredUseCase isUserMfaRequiredUseCase;

    /** Resolves the client of a request. */
    @Mock
    private RegisteredClientRepository registeredClientRepository;

    /** Manager under test. */
    private MfaAuthorizationManager manager;

    /**
     * Creates the manager under test.
     */
    @BeforeEach
    void setUp() {
        manager = new MfaAuthorizationManager(mfaPolicy, factorRegistry, isUserMfaRequiredUseCase,
                registeredClientRepository);
    }

    /**
     * Verifies that a password-only user is granted when neither the client nor the user requires MFA.
     */
    @Test
    void evaluate_whenMfaIsNotRequired_grantsPasswordOnly() {
        when(isUserMfaRequiredUseCase.execute(USERNAME)).thenReturn(false);

        assertTrue(manager.evaluate(user(FactorGrantedAuthority.PASSWORD_AUTHORITY), false).isGranted());
    }

    /**
     * Verifies that a password-only user is refused, naming the TOTP factor, when the client requires MFA.
     */
    @Test
    void evaluate_whenClientRequiresMfaAndOnlyPasswordWasUsed_refusesNamingMissingSecondFactor() {
        when(isUserMfaRequiredUseCase.execute(USERNAME)).thenReturn(false);

        final var result = manager.evaluate(user(FactorGrantedAuthority.PASSWORD_AUTHORITY), true);

        final var decision = assertInstanceOf(FactorAuthorizationDecision.class, result);
        assertFalse(decision.isGranted());
        assertEquals(TOTP_AUTHORITY, decision.getFactorErrors().getFirst().getRequiredFactor().getAuthority());
        assertTrue(decision.getFactorErrors().getFirst().isMissing());
    }

    /**
     * Verifies that a password-only user is refused when the account requires MFA.
     */
    @Test
    void evaluate_whenUserRequiresMfaAndOnlyPasswordWasUsed_refuses() {
        when(isUserMfaRequiredUseCase.execute(USERNAME)).thenReturn(true);

        assertFalse(manager.evaluate(user(FactorGrantedAuthority.PASSWORD_AUTHORITY), false).isGranted());
    }

    /**
     * Verifies that a user with the password and the TOTP factors is granted when MFA is required.
     */
    @Test
    void evaluate_whenMfaIsRequiredAndBothFactorsWereUsed_grants() {
        when(isUserMfaRequiredUseCase.execute(USERNAME)).thenReturn(false);

        assertTrue(manager.evaluate(user(FactorGrantedAuthority.PASSWORD_AUTHORITY, TOTP_AUTHORITY), true)
                .isGranted());
    }

    /**
     * Verifies a plain refusal when MFA is required but no second factor is registered.
     */
    @Test
    void evaluate_whenNoSecondFactorIsRegistered_refusesWithoutFactorErrors() {
        final var passwordOnly = new AuthenticationFactorRegistry(List.of(
                new AuthenticationFactor("password", "pwd", FactorGrantedAuthority.PASSWORD_AUTHORITY,
                        FactorStrength.PRIMARY)));
        final var bare = new MfaAuthorizationManager(mfaPolicy, passwordOnly, isUserMfaRequiredUseCase,
                registeredClientRepository);
        when(isUserMfaRequiredUseCase.execute(USERNAME)).thenReturn(true);

        final var result = bare.evaluate(user(FactorGrantedAuthority.PASSWORD_AUTHORITY), false);

        assertFalse(result.isGranted());
        assertFalse(result instanceof FactorAuthorizationDecision);
    }

    /**
     * Verifies that a request is refused without consulting anything when nobody is signed in.
     */
    @Test
    void authorize_whenUserIsAnonymous_refuses() {
        final Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        final var result = manager.authorize(() -> anonymous, context(null));

        assertFalse(result.isGranted());
        verifyNoInteractions(isUserMfaRequiredUseCase, registeredClientRepository);
    }

    /**
     * Verifies that the client of the request, found by its identifier, makes MFA mandatory.
     */
    @Test
    void authorize_whenClientOfRequestRequiresMfa_refusesPasswordOnly() {
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(client(true));
        when(isUserMfaRequiredUseCase.execute(USERNAME)).thenReturn(false);
        final var authentication = user(FactorGrantedAuthority.PASSWORD_AUTHORITY);

        assertFalse(manager.authorize(() -> authentication, context(CLIENT_ID)).isGranted());
    }

    /**
     * Verifies that a request without client is judged on the user's flag only.
     */
    @Test
    void authorize_whenRequestHasNoClient_grantsPasswordOnlyUserWithoutFlag() {
        when(isUserMfaRequiredUseCase.execute(USERNAME)).thenReturn(false);
        final var authentication = user(FactorGrantedAuthority.PASSWORD_AUTHORITY);

        assertTrue(manager.authorize(() -> authentication, context(null)).isGranted());
        verifyNoInteractions(registeredClientRepository);
    }

    /**
     * Verifies the client flag: absent client, absent setting, true and false.
     */
    @Test
    void requiresMfa_whenClientIsNullOrSettingVaries_reflectsTheSetting() {
        assertFalse(MfaAuthorizationManager.requiresMfa(null));
        assertFalse(MfaAuthorizationManager.requiresMfa(clientWithSettings(ClientSettings.builder().build())));
        assertFalse(MfaAuthorizationManager.requiresMfa(client(false)));
        assertTrue(MfaAuthorizationManager.requiresMfa(client(true)));
    }

    /**
     * Verifies which authentications count as a signed-in user.
     */
    @Test
    void isUser_whenAuthenticationVaries_onlySignedInUsersCount() {
        assertFalse(MfaAuthorizationManager.isUser(null));
        assertFalse(MfaAuthorizationManager.isUser(UsernamePasswordAuthenticationToken.unauthenticated(USERNAME, "x")));
        assertTrue(MfaAuthorizationManager.isUser(user()));
    }

    /**
     * Builds an authenticated user holding factor authorities.
     *
     * @param authorities authorities of the user.
     * @return the authentication.
     */
    private static Authentication user(final String... authorities) {
        return UsernamePasswordAuthenticationToken.authenticated(USERNAME, null,
                AuthorityUtils.createAuthorityList(authorities));
    }

    /**
     * Builds the context of a request.
     *
     * @param clientId the {@code client_id} parameter, may be {@code null}.
     * @return the context.
     */
    private static RequestAuthorizationContext context(final String clientId) {
        final var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        if (clientId != null) {
            request.setParameter("client_id", clientId);
        }
        return new RequestAuthorizationContext(request);
    }

    /**
     * Builds a client with the MFA setting.
     *
     * @param required the value of the setting.
     * @return the client.
     */
    private static RegisteredClient client(final boolean required) {
        return clientWithSettings(ClientSettings.builder()
                .setting(MfaAuthorizationManager.CLIENT_MFA_REQUIRED_SETTING, required).build());
    }

    /**
     * Builds a client with settings.
     *
     * @param settings the settings.
     * @return the client.
     */
    private static RegisteredClient clientWithSettings(final ClientSettings settings) {
        return RegisteredClient.withId("id").clientId(CLIENT_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example/cb").clientSettings(settings).build();
    }
}
