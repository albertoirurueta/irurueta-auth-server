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

package com.irurueta.authserver.authorization.application.clients;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import java.time.Duration;
import java.util.List;

/**
 * The single definition of the clients every deployment starts with: the confidential {@code bff} (backend for
 * frontend) and the public {@code spa-public}. Used by the seeder and by the development data initializer, so they
 * never drift apart. Both carry the audience of the resource server.
 */
public final class DefaultClientDefinitions {

    /** Client id of the backend for frontend. */
    public static final String BFF_CLIENT_ID = "bff";

    /** Client id of the public single-page application. */
    public static final String SPA_PUBLIC_CLIENT_ID = "spa-public";

    /** Redirect URI of the backend for frontend. */
    public static final String BFF_REDIRECT_URI = "http://localhost:8080/login/oauth2/code/bff";

    /** Redirect URI of the single-page application. */
    public static final String SPA_REDIRECT_URI = "http://localhost:3000/callback";

    /** Audience of the resource server. */
    public static final String RESOURCE_SERVER_AUDIENCE = "resource-server";

    /** Lifetime of access tokens. */
    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(10);

    /** Lifetime of refresh tokens. */
    private static final Duration REFRESH_TOKEN_TTL = Duration.ofHours(8);

    /** Not instantiable. */
    private DefaultClientDefinitions() {
    }

    // tag::clients-seed[]
    /**
     * Defines the {@code bff} client: confidential, {@code client_secret_basic}, authorization code with PKCE and
     * refresh tokens, with refresh token rotation on.
     *
     * @return the client.
     */
    public static ClientRegistration bff() {
        return new ClientRegistration(BFF_CLIENT_ID, "Backend for Frontend", true,
                List.of("client_secret_basic"), List.of("authorization_code", "refresh_token"),
                List.of(BFF_REDIRECT_URI), List.of("openid", "profile"), true,
                List.of(RESOURCE_SERVER_AUDIENCE), ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false);
    }

    /**
     * Defines the {@code spa-public} client: public, authorization code with PKCE, no client authentication.
     *
     * @return the client.
     */
    public static ClientRegistration spaPublic() {
        return new ClientRegistration(SPA_PUBLIC_CLIENT_ID, "Single-page application", false,
                List.of("none"), List.of("authorization_code", "refresh_token"),
                List.of(SPA_REDIRECT_URI), List.of("openid", "profile"), true,
                List.of(RESOURCE_SERVER_AUDIENCE), ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false);
    }

    /**
     * Lists every default client.
     *
     * @return the clients.
     */
    public static List<ClientRegistration> all() {
        return List.of(bff(), spaPublic());
    }
    // end::clients-seed[]
}
