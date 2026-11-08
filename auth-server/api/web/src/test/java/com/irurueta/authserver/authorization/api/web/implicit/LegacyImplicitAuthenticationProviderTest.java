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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * Unit tests of {@link LegacyImplicitAuthenticationProvider}.
 */
@ExtendWith(MockitoExtension.class)
class LegacyImplicitAuthenticationProviderTest {

    /** Client id. */
    private static final String CLIENT_ID = "legacy-implicit-spa";

    /** Registered redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /** Scope of the client. */
    private static final String SCOPE = "documents.read";

    /** State of the request. */
    private static final String STATE = "state-1";

    /** Lifetime of the generated token in seconds. */
    private static final long LIFETIME = 300;

    /** Lifetime of the client's tokens. */
    private static final Duration SHORT_TTL = Duration.ofMinutes(5);

    /** Longest lifetime of the flow. */
    private static final Duration MAX_TTL = Duration.ofMinutes(15);

    /** Finds the client. */
    @Mock
    private RegisteredClientRepository registeredClients;

    /** Stores the authorization. */
    @Mock
    private OAuth2AuthorizationService authorizationService;

    /** Generates the token. */
    @Mock
    private OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

    /** Applies the multi-factor policy. */
    @Mock
    private MfaAuthorizationManager authorizationManager;

    /**
     * Sets the context of the authorization server, which the framework sets for every request.
     */
    @BeforeEach
    void setAuthorizationServerContext() {
        AuthorizationServerContextHolder.setContext(mock(AuthorizationServerContext.class));
    }

    /**
     * Clears the context of the authorization server.
     */
    @AfterEach
    void clearAuthorizationServerContext() {
        AuthorizationServerContextHolder.resetContext();
    }

    /**
     * Verifies that a valid request gets an access token, stored without refresh token.
     */
    @Test
    void authenticate_whenTheRequestIsValid_issuesAndStoresTheToken() {
        final var client = client(SHORT_TTL);
        stubClient(client);
        stubGranted();
        final var jwt = jwt();
        when(tokenGenerator.generate(any())).thenReturn(jwt);

        final var result = assertInstanceOf(LegacyImplicitAccessTokenToken.class,
                provider().authenticate(request(Set.of(SCOPE), REDIRECT_URI, STATE, user())));

        assertEquals("jwt", result.getAccessToken().getTokenValue());
        assertEquals(Set.of(SCOPE), result.getScopes());
        assertEquals(REDIRECT_URI, result.getRedirectUri());
        assertEquals(STATE, result.getState());
        final var captor = ArgumentCaptor.<OAuth2Authorization>captor();
        verify(authorizationService).save(captor.capture());
        final var stored = captor.getValue();
        assertEquals("alice", stored.getPrincipalName());
        assertEquals(LegacyImplicitAuthenticationProvider.IMPLICIT, stored.getAuthorizationGrantType());
        assertNull(stored.getRefreshToken());
        assertEquals("jwt", stored.getAccessToken().getToken().getTokenValue());
        assertFalse(stored.getAccessToken().isInvalidated());
        assertEquals(jwt.getClaims(), stored.getAccessToken().getClaims());
    }

    /**
     * Verifies that a request without scopes gets the scopes of the client.
     */
    @Test
    void authenticate_whenNoScopeIsRequested_grantsTheScopesOfTheClient() {
        stubClient(client(SHORT_TTL));
        stubGranted();
        when(tokenGenerator.generate(any())).thenReturn(jwt());

        final var result = assertInstanceOf(LegacyImplicitAccessTokenToken.class,
                provider().authenticate(request(Set.of(), REDIRECT_URI, STATE, user())));

        assertEquals(Set.of(SCOPE), result.getScopes());
    }

    /**
     * Verifies that the token context uses the grant {@code implicit}, the user and a lifetime capped at the
     * maximum of the flow.
     */
    @Test
    void authenticate_whenTheClientLifetimeIsTooLong_capsTheLifetimeOfTheToken() {
        stubClient(client(Duration.ofHours(1)));
        stubGranted();
        when(tokenGenerator.generate(any())).thenReturn(jwt());
        final var user = user();

        provider().authenticate(request(Set.of(SCOPE), REDIRECT_URI, STATE, user));

        final var captor = ArgumentCaptor.<OAuth2TokenContext>captor();
        verify(tokenGenerator).generate(captor.capture());
        final var context = captor.getValue();
        assertEquals(MAX_TTL, context.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
        assertEquals(LegacyImplicitAuthenticationProvider.IMPLICIT, context.getAuthorizationGrantType());
        assertEquals(OAuth2TokenType.ACCESS_TOKEN, context.getTokenType());
        assertEquals(user, context.getPrincipal());
    }

    /**
     * Verifies that a shorter lifetime of the client is kept.
     */
    @Test
    void authenticate_whenTheClientLifetimeIsShorter_keepsIt() {
        stubClient(client(SHORT_TTL));
        stubGranted();
        when(tokenGenerator.generate(any())).thenReturn(jwt());

        provider().authenticate(request(Set.of(SCOPE), REDIRECT_URI, STATE, user()));

        final var captor = ArgumentCaptor.<OAuth2TokenContext>captor();
        verify(tokenGenerator).generate(captor.capture());
        assertEquals(SHORT_TTL,
                captor.getValue().getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
    }

    /**
     * Verifies that a generator that produces nothing is a server error.
     */
    @Test
    void authenticate_whenNoTokenIsGenerated_throwsServerError() {
        stubClient(client(SHORT_TTL));
        stubGranted();
        when(tokenGenerator.generate(any())).thenReturn(null);
        final var request = request(Set.of(SCOPE), REDIRECT_URI, STATE, user());
        final var provider = provider();

        final var error = assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(request));

        assertEquals("server_error", error.getError().getErrorCode());
        verifyNoInteractions(authorizationService);
    }

    /**
     * Verifies that an unknown client is refused without redirect.
     */
    @Test
    void authenticate_whenTheClientIsUnknown_throwsUnsupportedResponseType() {
        when(registeredClients.findByClientId(CLIENT_ID)).thenReturn(null);

        assertRefusal("unsupported_response_type", request(Set.of(SCOPE), REDIRECT_URI, STATE, user()));
    }

    /**
     * Verifies that a client without the implicit grant is refused without redirect.
     */
    @Test
    void authenticate_whenTheClientHasNoImplicitGrant_throwsUnauthorizedClient() {
        final var client = RegisteredClient.withId("id").clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI).scope(SCOPE).build();
        stubClient(client);

        assertRefusal("unauthorized_client", request(Set.of(SCOPE), REDIRECT_URI, STATE, user()));
    }

    /**
     * Verifies that a missing or unregistered redirect URI is refused without redirect, even a near match.
     */
    @Test
    void authenticate_whenTheRedirectUriIsNotRegistered_throwsInvalidRequest() {
        stubClient(client(SHORT_TTL));

        assertRefusal("invalid_request", request(Set.of(SCOPE), null, STATE, user()));
        assertRefusal("invalid_request", request(Set.of(SCOPE), "http://localhost:9000/legacy-implicit", STATE, user()));
        assertRefusal("invalid_request", request(Set.of(SCOPE), "http://evil.example/cb", STATE, user()));
        verifyNoInteractions(authorizationService);
    }

    /**
     * Verifies that an anonymous user is refused without redirect.
     */
    @Test
    void authenticate_whenTheUserIsAnonymous_throwsInvalidRequest() {
        stubClient(client(SHORT_TTL));
        final Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertRefusal("invalid_request", request(Set.of(SCOPE), REDIRECT_URI, STATE, anonymous));
    }

    /**
     * Verifies that a user who still owes a second factor is sent to give it.
     */
    @Test
    void authenticate_whenTheSecondFactorIsMissing_throwsSecondFactorRequired() {
        stubClient(client(SHORT_TTL));
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(false);
        when(authorizationManager.evaluate(any(), anyBoolean())).thenReturn(new AuthorizationDecision(false));
        final var request = request(Set.of(SCOPE), REDIRECT_URI, STATE, user());
        final var provider = provider();

        assertThrows(SecondFactorRequiredException.class, () -> provider.authenticate(request));
        verify(tokenGenerator, never()).generate(any());
    }

    /**
     * Verifies that a request without state gets the error in the fragment, without echoing a state.
     */
    @Test
    void authenticate_whenStateIsMissing_returnsInvalidRequestError() {
        stubClient(client(SHORT_TTL));
        stubGranted();

        final var result = assertInstanceOf(LegacyImplicitErrorToken.class,
                provider().authenticate(request(Set.of(SCOPE), REDIRECT_URI, " ", user())));

        assertEquals("invalid_request", result.getError());
        assertEquals(REDIRECT_URI, result.getRedirectUri());
        assertNull(result.getState());
        verifyNoInteractions(authorizationService);
    }

    /**
     * Verifies that a scope the client may not request gets the error in the fragment.
     */
    @Test
    void authenticate_whenAScopeIsNotAllowed_returnsInvalidScopeError() {
        stubClient(client(SHORT_TTL));
        stubGranted();

        final var result = assertInstanceOf(LegacyImplicitErrorToken.class,
                provider().authenticate(request(Set.of(SCOPE, "documents.delete"), REDIRECT_URI, STATE, user())));

        assertEquals("invalid_scope", result.getError());
        assertEquals(STATE, result.getState());
        verifyNoInteractions(authorizationService);
    }

    /**
     * Verifies which requests the provider handles.
     */
    @Test
    void supports_whenTheTypeIsALegacyRequest_returnsTrue() {
        final var provider = provider();

        assertTrue(provider.supports(LegacyImplicitAuthorizationRequestToken.class));
        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    /**
     * Verifies that the multi-factor policy is applied with the requirement of the client.
     */
    @Test
    void authenticate_whenTheClientRequiresMfa_appliesThePolicyWithIt() {
        stubClient(client(SHORT_TTL));
        when(authorizationManager.clientRequiresMfa(CLIENT_ID)).thenReturn(true);
        when(authorizationManager.evaluate(any(), eq(true))).thenReturn(new AuthorizationDecision(true));
        when(tokenGenerator.generate(any())).thenReturn(jwt());

        provider().authenticate(request(Set.of(SCOPE), REDIRECT_URI, STATE, user()));

        verify(authorizationManager).evaluate(any(), eq(true));
    }

    /**
     * Creates the provider under test.
     *
     * @return the provider.
     */
    private LegacyImplicitAuthenticationProvider provider() {
        return new LegacyImplicitAuthenticationProvider(registeredClients, authorizationService, tokenGenerator,
                authorizationManager, MAX_TTL);
    }

    /**
     * Makes the repository find the client.
     *
     * @param client the client.
     */
    private void stubClient(final RegisteredClient client) {
        when(registeredClients.findByClientId(CLIENT_ID)).thenReturn(client);
    }

    /**
     * Makes the multi-factor policy grant the user.
     */
    private void stubGranted() {
        when(authorizationManager.evaluate(any(), anyBoolean())).thenReturn(new AuthorizationDecision(true));
    }

    /**
     * Asserts that the request is refused with a redirect-less error.
     *
     * @param code    the expected error code.
     * @param request the request.
     */
    private void assertRefusal(final String code, final LegacyImplicitAuthorizationRequestToken request) {
        final var provider = provider();
        final var error = assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> provider.authenticate(request));

        assertEquals(code, error.getError().getErrorCode());
        assertNull(error.getAuthorizationCodeRequestAuthentication());
    }

    /**
     * Builds the request.
     *
     * @param scopes      scopes requested.
     * @param redirectUri redirect URI, may be {@code null}.
     * @param state       state, may be {@code null}.
     * @param user        the user.
     * @return the request.
     */
    private static LegacyImplicitAuthorizationRequestToken request(final Set<String> scopes, final String redirectUri,
            final String state, final Authentication user) {
        return new LegacyImplicitAuthorizationRequestToken(CLIENT_ID, redirectUri, scopes, state, user);
    }

    /**
     * Builds the signed-in user.
     *
     * @return the user.
     */
    private static Authentication user() {
        return UsernamePasswordAuthenticationToken.authenticated("alice", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    /**
     * Builds the client of the legacy flow.
     *
     * @param ttl lifetime of its access tokens.
     * @return the client.
     */
    private static RegisteredClient client(final Duration ttl) {
        return RegisteredClient.withId("id").clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(LegacyImplicitAuthenticationProvider.IMPLICIT)
                .redirectUri(REDIRECT_URI).scopes(scopes -> scopes.addAll(List.of(SCOPE)))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(ttl).build()).build();
    }

    /**
     * Builds the token the generator returns.
     *
     * @return the JWT.
     */
    private static Jwt jwt() {
        final var now = Instant.now();
        return Jwt.withTokenValue("jwt").header("alg", "none").subject("alice").issuedAt(now)
                .expiresAt(now.plusSeconds(LIFETIME)).build();
    }
}
