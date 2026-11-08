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
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * The result of a granted legacy implicit request: the access token and what the response needs to send it to the
 * client in the fragment of its redirect URI.
 */
public class LegacyImplicitAccessTokenToken extends AbstractAuthenticationToken {

    /** Serial version. */
    private static final long serialVersionUID = 1L;

    /** The access token issued. */
    private final transient OAuth2AccessToken accessToken;

    /** Scopes granted. */
    private final Set<String> scopes;

    /** The registered redirect URI the token is sent to. */
    private final String redirectUri;

    /** State of the request, {@code null} when it had none. */
    private final String state;

    /**
     * Creates the result.
     *
     * @param accessToken the access token issued.
     * @param scopes      scopes granted.
     * @param redirectUri the registered redirect URI.
     * @param state       state of the request, may be {@code null}.
     */
    public LegacyImplicitAccessTokenToken(final OAuth2AccessToken accessToken, final Set<String> scopes,
            final String redirectUri, final String state) {
        super(List.of());
        this.accessToken = accessToken;
        this.scopes = Set.copyOf(scopes);
        this.redirectUri = redirectUri;
        this.state = state;
        setAuthenticated(true);
    }

    /**
     * Returns the access token issued.
     *
     * @return the token.
     */
    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }

    /**
     * Returns the scopes granted.
     *
     * @return the scopes.
     */
    public Set<String> getScopes() {
        return scopes;
    }

    /**
     * Returns the redirect URI the token is sent to.
     *
     * @return the redirect URI.
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Returns the state of the request.
     *
     * @return the state, {@code null} when the request had none.
     */
    public String getState() {
        return state;
    }

    /**
     * Returns the credentials, which a result has none of.
     *
     * @return an empty string.
     */
    @Override
    public Object getCredentials() {
        return "";
    }

    /**
     * Returns the principal of the result: the token value is deliberately not it, so it is never logged.
     *
     * @return the redirect URI.
     */
    @Override
    public Object getPrincipal() {
        return redirectUri;
    }
}
