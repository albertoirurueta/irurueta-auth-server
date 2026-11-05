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

package com.irurueta.authserver.authorization.api.web.clients;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Duration;
import java.util.List;

/**
 * Public view of a registered client. It never contains a secret.
 *
 * @param clientId          public identifier of the client.
 * @param name              human readable name.
 * @param confidential      whether the client can keep a secret.
 * @param authMethods       client authentication methods.
 * @param grantTypes        allowed grant types.
 * @param redirectUris      allowed redirect URIs.
 * @param scopes            allowed scopes.
 * @param requireProofKey   whether PKCE is required.
 * @param audiences         audiences of the issued access tokens.
 * @param accessTokenTtl    lifetime of access tokens.
 * @param refreshTokenTtl   lifetime of refresh tokens.
 * @param accessTokenFormat format of access tokens.
 * @param reuseRefreshTokens whether refresh tokens are reused instead of rotated.
 */
@Schema(description = "A registered client, without any secret")
public record ClientResponse(
        String clientId, String name, boolean confidential, List<String> authMethods, List<String> grantTypes,
        List<String> redirectUris, List<String> scopes, boolean requireProofKey, List<String> audiences,
        Duration accessTokenTtl, Duration refreshTokenTtl, String accessTokenFormat, boolean reuseRefreshTokens) {

    /**
     * Creates a response, copying its collections.
     */
    public ClientResponse {
        authMethods = List.copyOf(authMethods);
        grantTypes = List.copyOf(grantTypes);
        redirectUris = List.copyOf(redirectUris);
        scopes = List.copyOf(scopes);
        audiences = List.copyOf(audiences);
    }

    /**
     * Maps a registration.
     *
     * @param registration the registration.
     * @return its public view.
     */
    public static ClientResponse from(final ClientRegistration registration) {
        return new ClientResponse(registration.clientId(), registration.name(), registration.confidential(),
                registration.authMethods(), registration.grantTypes(), registration.redirectUris(),
                registration.scopes(), registration.requireProofKey(), registration.audiences(),
                registration.accessTokenTtl(), registration.refreshTokenTtl(), registration.accessTokenFormat(),
                registration.reuseRefreshTokens());
    }
}
