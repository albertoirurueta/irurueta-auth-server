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

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredException;
import java.security.Principal;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

// tag::implicit-provider[]
/**
 * Grants the legacy implicit request: after checking the client, its redirect URI, the user, the multi-factor policy,
 * the {@code state} and the scopes, it issues an access token (never a refresh token) through the token generator,
 * stores the authorization (so the token can be introspected and revoked) and returns it for the response handler.
 */
@RequiredArgsConstructor
public class LegacyImplicitAuthenticationProvider implements AuthenticationProvider {

    /** Grant type recorded for the tokens of the flow; the framework has no constant for it. */
    public static final AuthorizationGrantType IMPLICIT = new AuthorizationGrantType("implicit");

    /** Finds the client. */
    private final RegisteredClientRepository registeredClients;

    /** Stores the authorization behind the token. */
    private final OAuth2AuthorizationService authorizationService;

    /** Generates the access token, with the claims of the other flows. */
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    /** Applies the multi-factor policy. */
    private final MfaAuthorizationManager authorizationManager;

    /** Longest lifetime of the tokens of the flow. */
    private final Duration maxAccessTokenTtl;

    /**
     * Grants or refuses the request.
     *
     * @param authentication the request, a {@link LegacyImplicitAuthorizationRequestToken}.
     * @return the access token, or the error that must be sent in the fragment of the redirect URI.
     * @throws AuthenticationException {@code unsupported_response_type} or {@code unauthorized_client} when the
     *                                 client is unknown or may not use the flow, {@code invalid_request} when the
     *                                 redirect URI is missing or not registered or the user is not signed in (none
     *                                 of them redirects), {@link SecondFactorRequiredException} when the user owes a
     *                                 second factor, or {@code server_error} when no token can be generated.
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final var request = (LegacyImplicitAuthorizationRequestToken) authentication;
        final var client = registeredClients.findByClientId(request.getClientId());
        if (client == null) {
            throw refused(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE);
        }
        if (!client.getAuthorizationGrantTypes().contains(IMPLICIT)) {
            throw refused(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        final var redirectUri = request.getRedirectUri();
        if (redirectUri == null || !client.getRedirectUris().contains(redirectUri)) {
            throw refused(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        final var user = (Authentication) request.getPrincipal();
        if (!MfaAuthorizationManager.isUser(user)) {
            throw refused(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        if (!authorizationManager.evaluate(user, authorizationManager.clientRequiresMfa(client.getClientId()))
                .isGranted()) {
            throw new SecondFactorRequiredException();
        }
        final var state = request.getState();
        if (state == null || state.isBlank()) {
            return new LegacyImplicitErrorToken(OAuth2ErrorCodes.INVALID_REQUEST, "state is required", redirectUri,
                    null);
        }
        final Set<String> scopes = request.getScopes().isEmpty()
                ? new LinkedHashSet<>(client.getScopes()) : new LinkedHashSet<>(request.getScopes());
        if (!client.getScopes().containsAll(scopes)) {
            return new LegacyImplicitErrorToken(OAuth2ErrorCodes.INVALID_SCOPE, null, redirectUri, state);
        }
        return issue(request, client, user, scopes);
    }

    /**
     * Tells which requests this provider handles.
     *
     * @param authentication the type of the request.
     * @return {@code true} for a request of the legacy flow.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return LegacyImplicitAuthorizationRequestToken.class.isAssignableFrom(authentication);
    }

    /**
     * Issues and stores the access token.
     *
     * @param request the request.
     * @param client  the client.
     * @param user    the signed-in user.
     * @param scopes  the scopes granted.
     * @return the result.
     */
    private LegacyImplicitAccessTokenToken issue(final LegacyImplicitAuthorizationRequestToken request,
            final RegisteredClient client, final Authentication user, final Set<String> scopes) {
        final var cappedClient = withCappedLifetime(client);
        final var context = DefaultOAuth2TokenContext.builder()
                .registeredClient(cappedClient)
                .principal(user)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(IMPLICIT)
                .authorizationGrant(request)
                .build();
        final OAuth2Token generated = tokenGenerator.generate(context);
        if (generated == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", null));
        }
        final var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generated.getTokenValue(),
                generated.getIssuedAt(), generated.getExpiresAt(), scopes);
        final var claims = generated instanceof ClaimAccessor accessor ? accessor.getClaims() : null;
        final var format = client.getTokenSettings().getAccessTokenFormat().getValue();
        final var authorization = OAuth2Authorization.withRegisteredClient(client)
                .principalName(user.getName())
                .authorizationGrantType(IMPLICIT)
                .authorizedScopes(scopes)
                .attribute(Principal.class.getName(), user)
                .token(accessToken, metadata -> {
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
                    metadata.put(OAuth2TokenFormat.class.getName(), format);
                })
                .build();
        authorizationService.save(authorization);
        return new LegacyImplicitAccessTokenToken(accessToken, scopes, request.getRedirectUri(), request.getState());
    }

    /**
     * Copies the client with the lifetime of its access tokens limited to the maximum of the flow.
     *
     * @param client the client.
     * @return the client with the lifetime {@code min(client, maximum)}.
     */
    private RegisteredClient withCappedLifetime(final RegisteredClient client) {
        final var settings = client.getTokenSettings();
        if (settings.getAccessTokenTimeToLive().compareTo(maxAccessTokenTtl) <= 0) {
            return client;
        }
        return RegisteredClient.from(client)
                .tokenSettings(TokenSettings.withSettings(settings.getSettings())
                        .accessTokenTimeToLive(maxAccessTokenTtl).build())
                .build();
    }

    /**
     * Builds a refusal that is answered with {@code 400}, never redirected, because the redirect URI is not trusted
     * yet or the user cannot be sent anywhere.
     *
     * @param code error code.
     * @return the exception.
     */
    private static OAuth2AuthorizationCodeRequestAuthenticationException refused(final String code) {
        return new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(code), null);
    }
}
// end::implicit-provider[]
