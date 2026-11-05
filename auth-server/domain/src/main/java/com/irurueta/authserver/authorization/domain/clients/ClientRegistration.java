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
 */
public record ClientRegistration(
        String clientId, String name, boolean confidential, List<String> authMethods, List<String> grantTypes,
        List<String> redirectUris, List<String> scopes, boolean requireProofKey, List<String> audiences,
        Duration accessTokenTtl, Duration refreshTokenTtl, String accessTokenFormat, boolean reuseRefreshTokens) {

    /** Access token format of self-contained (JWT) tokens. */
    public static final String FORMAT_SELF_CONTAINED = "self-contained";

    /** Access token format of opaque, reference tokens. */
    public static final String FORMAT_REFERENCE = "reference";

    /**
     * Validates the registration and defensively copies its collections.
     *
     * @throws IllegalArgumentException if the id, name or format is blank, a collection is null or has a null
     *                                  element, a lifetime is missing or not positive, or a public client does not
     *                                  require PKCE.
     */
    public ClientRegistration {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be blank");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        if (accessTokenFormat == null || accessTokenFormat.isBlank()) {
            throw new IllegalArgumentException("accessTokenFormat must not be blank");
        }
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
        if (isNotPositive(accessTokenTtl) || isNotPositive(refreshTokenTtl)) {
            throw new IllegalArgumentException("token lifetimes must be positive");
        }
        if (!confidential && !requireProofKey) {
            throw new IllegalArgumentException("a public client must require PKCE");
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
