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

package com.irurueta.authserver.authorization.domain.clients;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;
import static com.irurueta.authserver.authorization.domain.Preconditions.requireTextIfPresent;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * An OAuth 2.1 client registered with the authorization server. The client secret is not part of the model: it is
 * only ever handled encoded, through the repository.
 *
 * @param clientId           public identifier of the client.
 * @param name               human readable name.
 * @param confidential       {@code true} for a client able to keep a secret, {@code false} for a public client.
 * @param authMethods        client authentication methods, for example {@code client_secret_basic} or {@code none}.
 * @param grantTypes         grant types the client may use, for example {@code authorization_code}.
 * @param redirectUris       redirect URIs the client may use.
 * @param scopes             scopes the client may request.
 * @param requireProofKey    whether the authorization code flow must use PKCE.
 * @param audiences          logical identifiers of the APIs the access tokens are meant for (the {@code aud} claim);
 *                           the client id when none is given.
 * @param accessTokenTtl     lifetime of access tokens.
 * @param refreshTokenTtl    lifetime of refresh tokens.
 * @param accessTokenFormat  {@code self-contained} or {@code reference}.
 * @param reuseRefreshTokens {@code true} to keep a refresh token after use, {@code false} to rotate it.
 * @param postLogoutRedirectUris URIs an end-user may be redirected to after an OpenID Connect RP-initiated logout;
 *                           a {@code post_logout_redirect_uri} that is not listed is never honoured.
 * @param requireConsent     whether the end-user must explicitly grant the requested scopes on a consent page.
 * @param mfaRequired        whether every user signing in through the client must complete a second factor.
 * @param jwkSetUrl          URL of the client's public JWK set, used to verify {@code private_key_jwt} assertions and
 *                           self-signed certificates; {@code null} when none.
 * @param jwks               the client's registered public JWK set as JSON (public keys only), alternative to
 *                           {@code jwkSetUrl}; {@code null} when none.
 * @param tokenEndpointSigningAlgorithm JWS algorithm the client signs its {@code private_key_jwt} assertions with;
 *                           {@code null} when unrestricted.
 * @param tlsClientAuthSubjectDn expected subject distinguished name of the certificate of a
 *                           {@code tls_client_auth} client; {@code null} when none.
 * @param certificateBoundAccessTokens whether access tokens are bound to the client certificate ({@code cnf.x5t#S256}).
 */
public record ClientRegistration(
        String clientId, String name, boolean confidential, List<String> authMethods, List<String> grantTypes,
        List<String> redirectUris, List<String> scopes, boolean requireProofKey, List<String> audiences,
        Duration accessTokenTtl, Duration refreshTokenTtl, String accessTokenFormat, boolean reuseRefreshTokens,
        List<String> postLogoutRedirectUris, boolean requireConsent, boolean mfaRequired, String jwkSetUrl, String jwks,
        String tokenEndpointSigningAlgorithm, String tlsClientAuthSubjectDn, boolean certificateBoundAccessTokens) {

    /** Access token format of self-contained (JWT) tokens. */
    public static final String FORMAT_SELF_CONTAINED = "self-contained";

    /** Grant type of the legacy implicit flow. */
    public static final String GRANT_IMPLICIT = "implicit";

    /** Grant type of refresh tokens. */
    public static final String GRANT_REFRESH_TOKEN = "refresh_token";

    /** Authentication method of a client that proves possession of a registered private key. */
    public static final String AUTH_PRIVATE_KEY_JWT = "private_key_jwt";

    /** Authentication method of mutual TLS with a certificate issued by a trusted authority. */
    public static final String AUTH_TLS_CLIENT_AUTH = "tls_client_auth";

    /** Authentication method of mutual TLS with a self-signed certificate. */
    public static final String AUTH_SELF_SIGNED_TLS_CLIENT_AUTH = "self_signed_tls_client_auth";

    /** Prefix of the authentication methods that use a client secret. */
    public static final String AUTH_CLIENT_SECRET_PREFIX = "client_secret_";

    /** Access token format of opaque, reference tokens. */
    public static final String FORMAT_REFERENCE = "reference";

    /**
     * Validates the registration and defensively copies its collections.
     *
     * @throws IllegalArgumentException if the id, name or format is blank, a collection is null or has a null
     *                                  element, a lifetime is missing or not positive, or a public client does not
     *                                  require PKCE (unless its only grant type is {@code implicit}), an
     *                                  {@code implicit} client is confidential, requires consent or has refresh
     *                                  tokens, a {@code tls_client_auth} client has no subject DN, a
     *                                  {@code private_key_jwt} or {@code self_signed_tls_client_auth} client has
     *                                  neither {@code jwks} nor {@code jwkSetUrl}, or a given optional text is blank.
     */
    public ClientRegistration {
        requireText(clientId, "clientId");
        requireText(name, "name");
        requireText(accessTokenFormat, "accessTokenFormat");
        requireNoNulls(authMethods, "authMethods");
        authMethods = List.copyOf(authMethods);
        requireNoNulls(grantTypes, "grantTypes");
        grantTypes = List.copyOf(grantTypes);
        requireNoNulls(redirectUris, "redirectUris");
        redirectUris = List.copyOf(redirectUris);
        requireNoNulls(scopes, "scopes");
        scopes = List.copyOf(scopes);
        requireNoNulls(audiences, "audiences");
        audiences = List.copyOf(audiences);
        if (audiences.isEmpty()) {
            audiences = List.of(clientId);
        }
        requireNoNulls(postLogoutRedirectUris, "postLogoutRedirectUris");
        postLogoutRedirectUris = List.copyOf(postLogoutRedirectUris);
        if (isNotPositive(accessTokenTtl) || isNotPositive(refreshTokenTtl)) {
            throw new IllegalArgumentException("token lifetimes must be positive");
        }
        requireTextIfPresent(jwkSetUrl, "jwkSetUrl");
        requireTextIfPresent(jwks, "jwks");
        requireTextIfPresent(tokenEndpointSigningAlgorithm, "tokenEndpointSigningAlgorithm");
        requireTextIfPresent(tlsClientAuthSubjectDn, "tlsClientAuthSubjectDn");
        if (!confidential && !requireProofKey && !grantTypes.equals(List.of(GRANT_IMPLICIT))) {
            throw new IllegalArgumentException("a public client must require PKCE");
        }
        if (grantTypes.contains(GRANT_IMPLICIT)) {
            requireValidImplicit(confidential, requireConsent, grantTypes);
        }
        if (authMethods.contains(AUTH_TLS_CLIENT_AUTH) && tlsClientAuthSubjectDn == null) {
            throw new IllegalArgumentException("tls_client_auth requires a subject DN");
        }
        if ((authMethods.contains(AUTH_PRIVATE_KEY_JWT) || authMethods.contains(AUTH_SELF_SIGNED_TLS_CLIENT_AUTH))
                && jwks == null && jwkSetUrl == null) {
            throw new IllegalArgumentException(
                    "private_key_jwt and self_signed_tls_client_auth require jwks or jwkSetUrl");
        }
    }

    /**
     * Tells whether the client authenticates with a client secret.
     *
     * @return {@code true} when any authentication method is a {@code client_secret_*} one.
     */
    public boolean usesClientSecret() {
        return authMethods.stream().anyMatch(method -> method.startsWith(AUTH_CLIENT_SECRET_PREFIX));
    }

    /**
     * Refuses an {@code implicit} client that is confidential, requires consent or may use refresh tokens.
     *
     * @param confidential whether the client is confidential.
     * @param requireConsent whether consent is required.
     * @param grantTypes the grant types of the client.
     */
    private static void requireValidImplicit(
            final boolean confidential, final boolean requireConsent, final List<String> grantTypes) {
        if (confidential) {
            throw new IllegalArgumentException("an implicit client must be public");
        }
        if (requireConsent) {
            throw new IllegalArgumentException("an implicit client cannot require consent");
        }
        if (grantTypes.contains(GRANT_REFRESH_TOKEN)) {
            throw new IllegalArgumentException("an implicit client cannot have refresh tokens");
        }
    }

    /**
     * Tells whether a duration is missing, zero or negative.
     *
     * @param duration the duration.
     * @return {@code true} when it is not a positive duration.
     */
    private static boolean isNotPositive(final Duration duration) {
        return duration == null || duration.isZero() || duration.isNegative();
    }

    /**
     * Rejects a null list and a list with null elements.
     *
     * @param values the list.
     * @param name   name of the list, for the message.
     */
    private static void requireNoNulls(final List<String> values, final String name) {
        if (values == null || values.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException(name + " must not be null or contain null elements");
        }
    }
}
