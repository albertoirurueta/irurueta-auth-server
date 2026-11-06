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
 * The single definition of the clients a deployment can start with: the confidential {@code bff} (backend for
 * frontend) and the public {@code spa-public}. Used by the seeder and by the development data initializer, so they
 * never drift apart. Nothing environment-specific lives here: the redirect URIs come from configuration (the
 * {@code dev} profile supplies the local ones) and so does the audience of the authorization server's own API. Both
 * clients carry the audience of the resource server and of that API (so a user can change their password through
 * them), may read and delete documents, and never get the {@code admin} scope.
 */
public final class DefaultClientDefinitions {

    /** Client id of the backend for frontend. */
    public static final String BFF_CLIENT_ID = "bff";

    /** Client id of the public single-page application. */
    public static final String SPA_PUBLIC_CLIENT_ID = "spa-public";

    /** Audience of the resource server. */
    public static final String RESOURCE_SERVER_AUDIENCE = "resource-server";

    /** Default audience of the authorization server's own REST API ({@code authserver.api.audience}). */
    public static final String DEFAULT_API_AUDIENCE = "auth-server";

    /** Scopes of both default clients. */
    private static final List<String> SCOPES = List.of("openid", "profile", "documents.read", "documents.delete");

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
     * refresh tokens, with refresh token rotation on. It requires the end-user's consent to the requested scopes.
     *
     * @param redirectUris redirect URIs of the deployment.
     * @param apiAudience  audience of the authorization server's own API.
     * @return the client.
     */
    public static ClientRegistration bff(final List<String> redirectUris, final String apiAudience) {
        return bff(redirectUris, apiAudience, List.of());
    }

    /**
     * Defines the {@code bff} client with the URIs it may be sent to after an OpenID Connect RP-initiated logout.
     *
     * @param redirectUris           redirect URIs of the deployment.
     * @param apiAudience            audience of the authorization server's own API.
     * @param postLogoutRedirectUris post-logout redirect URIs of the deployment; none when empty.
     * @return the client.
     */
    public static ClientRegistration bff(final List<String> redirectUris, final String apiAudience,
                                         final List<String> postLogoutRedirectUris) {
        return new ClientRegistration(BFF_CLIENT_ID, "Backend for Frontend", true,
                List.of("client_secret_basic"), List.of("authorization_code", "refresh_token"),
                redirectUris, SCOPES, true, List.of(RESOURCE_SERVER_AUDIENCE, apiAudience), ACCESS_TOKEN_TTL,
                REFRESH_TOKEN_TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false,
                postLogoutRedirectUris, true, false);
    }

    /**
     * Defines the {@code spa-public} client: public, authorization code with PKCE, no client authentication.
     *
     * @param redirectUris redirect URIs of the deployment.
     * @param apiAudience  audience of the authorization server's own API.
     * @return the client.
     */
    public static ClientRegistration spaPublic(final List<String> redirectUris, final String apiAudience) {
        return spaPublic(redirectUris, apiAudience, List.of());
    }

    /**
     * Defines the {@code spa-public} client with the URIs it may be sent to after an OpenID Connect RP-initiated
     * logout.
     *
     * @param redirectUris           redirect URIs of the deployment.
     * @param apiAudience            audience of the authorization server's own API.
     * @param postLogoutRedirectUris post-logout redirect URIs of the deployment; none when empty.
     * @return the client.
     */
    public static ClientRegistration spaPublic(final List<String> redirectUris, final String apiAudience,
                                               final List<String> postLogoutRedirectUris) {
        return new ClientRegistration(SPA_PUBLIC_CLIENT_ID, "Single-page application", false,
                List.of("none"), List.of("authorization_code", "refresh_token"),
                redirectUris, SCOPES, true, List.of(RESOURCE_SERVER_AUDIENCE, apiAudience), ACCESS_TOKEN_TTL,
                REFRESH_TOKEN_TTL, ClientRegistration.FORMAT_SELF_CONTAINED, false,
                postLogoutRedirectUris, false, false);
    }
    // end::clients-seed[]
}
