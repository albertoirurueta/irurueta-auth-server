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

import java.util.List;
import java.util.Set;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * An authorization request of the legacy implicit flow ({@code response_type=token}), not yet authenticated: the
 * request as the client sent it and the user the request arrived with.
 */
public class LegacyImplicitAuthorizationRequestToken extends AbstractAuthenticationToken {

    /** Serial version. */
    private static final long serialVersionUID = 1L;

    /** Identifier of the client. */
    private final String clientId;

    /** Redirect URI of the request, {@code null} when it names none. */
    private final String redirectUri;

    /** Scopes requested. */
    private final Set<String> scopes;

    /** State of the request, {@code null} when it has none. */
    private final String state;

    /** The user the request arrived with, possibly anonymous. */
    private final transient Authentication user;

    /**
     * Creates the request.
     *
     * @param clientId    identifier of the client.
     * @param redirectUri redirect URI of the request, may be {@code null}.
     * @param scopes      scopes requested.
     * @param state       state of the request, may be {@code null}.
     * @param user        the user the request arrived with.
     */
    public LegacyImplicitAuthorizationRequestToken(final String clientId, final String redirectUri,
            final Set<String> scopes, final String state, final Authentication user) {
        super(List.of());
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scopes = Set.copyOf(scopes);
        this.state = state;
        this.user = user;
    }

    /**
     * Returns the identifier of the client.
     *
     * @return the client id.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Returns the redirect URI of the request.
     *
     * @return the redirect URI, {@code null} when the request names none.
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Returns the scopes requested.
     *
     * @return the scopes, possibly empty.
     */
    public Set<String> getScopes() {
        return scopes;
    }

    /**
     * Returns the state of the request.
     *
     * @return the state, {@code null} when the request has none.
     */
    public String getState() {
        return state;
    }

    /**
     * Returns the credentials, which a request has none of.
     *
     * @return an empty string.
     */
    @Override
    public Object getCredentials() {
        return "";
    }

    /**
     * Returns the principal of the request: the user it arrived with.
     *
     * @return the user.
     */
    @Override
    public Object getPrincipal() {
        return user;
    }
}
