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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationEndpointConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Unit tests of {@link MfaProtocolChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class MfaProtocolChainCustomizerTest {

    /** Redirect URI of the client. */
    private static final String REDIRECT_URI = "https://client.example/cb";

    /** Identifier of the client. */
    private static final String CLIENT_ID = "client";

    /** Scope requested. */
    private static final String SCOPE = "openid";

    /** Manager that applies the policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /** Handler of the endpoint's errors. */
    @Mock
    private AuthenticationFailureHandler errorResponseHandler;

    /** Provider of the authorization code request. */
    @Mock
    private OAuth2AuthorizationCodeRequestAuthenticationProvider codeProvider;

    /** Validator installed in the provider, once the customizer ran. */
    private Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> validator;

    /**
     * Runs the customizer against mocked configurers and captures the validator it installs.
     */
    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        final var customizer = new MfaProtocolChainCustomizer(authorizationManager, errorResponseHandler);
        final var server = mock(OAuth2AuthorizationServerConfigurer.class);
        final var endpoint = mock(OAuth2AuthorizationEndpointConfigurer.class);
        final var serverCaptor = ArgumentCaptor.<Customizer<OAuth2AuthorizationEndpointConfigurer>>captor();
        final var providersCaptor = ArgumentCaptor.<Consumer<List<AuthenticationProvider>>>captor();
        when(server.authorizationEndpoint(serverCaptor.capture())).thenReturn(server);
        when(endpoint.authenticationProviders(providersCaptor.capture())).thenReturn(endpoint);
        when(endpoint.errorResponseHandler(any())).thenReturn(endpoint);

        customizer.customize(server);
        serverCaptor.getValue().customize(endpoint);
        final var providers = new ArrayList<AuthenticationProvider>();
        providers.add(mock(AuthenticationProvider.class));
        providers.add(codeProvider);
        providersCaptor.getValue().accept(providers);

        verify(endpoint).errorResponseHandler(errorResponseHandler);
        final var validatorCaptor = ArgumentCaptor
                .<Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext>>captor();
        verify(codeProvider).setAuthenticationValidator(validatorCaptor.capture());
        validator = validatorCaptor.getValue();
    }

    /**
     * Verifies that a user who owes a second factor is stopped by a {@link SecondFactorRequiredException}.
     */
    @Test
    void validator_whenPolicyIsNotSatisfied_throwsSecondFactorRequiredException() {
        final var user = user();
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(true);
        when(authorizationManager.evaluate(user, true)).thenReturn(new AuthorizationDecision(false));
        final var context = context(user);

        assertThrows(SecondFactorRequiredException.class, () -> validator.accept(context));
    }

    /**
     * Verifies that a user who satisfies the policy goes on.
     */
    @Test
    void validator_whenPolicyIsSatisfied_doesNotThrow() {
        final var user = user();
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(false);
        when(authorizationManager.evaluate(user, false)).thenReturn(new AuthorizationDecision(true));
        final var context = context(user);

        assertDoesNotThrow(() -> validator.accept(context));
    }

    /**
     * Verifies that a principal that is not signed in is left to the framework.
     */
    @Test
    void validator_whenPrincipalIsNotSignedIn_doesNotConsultThePolicy() {
        final var context = context(UsernamePasswordAuthenticationToken.unauthenticated("alice", "x"));

        assertDoesNotThrow(() -> validator.accept(context));
        verifyNoInteractions(authorizationManager);
    }

    /**
     * Builds a signed-in user.
     *
     * @return the authentication.
     */
    private static Authentication user() {
        return UsernamePasswordAuthenticationToken.authenticated("alice", null,
                AuthorityUtils.createAuthorityList("FACTOR_PASSWORD"));
    }

    /**
     * Builds the context of an authorization request.
     *
     * @param principal the user making the request.
     * @return the context.
     */
    private static OAuth2AuthorizationCodeRequestAuthenticationContext context(final Authentication principal) {
        final var client = RegisteredClient.withId("id").clientId(CLIENT_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri(REDIRECT_URI)
                .scope(SCOPE)
                .build();
        final var token = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://as.example/oauth2/authorize",
                CLIENT_ID, principal, REDIRECT_URI, "state", Set.of(SCOPE), Map.of());
        return OAuth2AuthorizationCodeRequestAuthenticationContext.with(token).registeredClient(client)
                .authorizationRequest(OAuth2AuthorizationRequest.authorizationCode()
                        .authorizationUri("https://as.example/oauth2/authorize").clientId(CLIENT_ID)
                        .redirectUri(REDIRECT_URI).scopes(Set.of(SCOPE)).state("state").build())
                .build();
    }
}
