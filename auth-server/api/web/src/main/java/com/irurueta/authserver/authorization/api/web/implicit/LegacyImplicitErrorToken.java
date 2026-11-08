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
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * The result of a legacy implicit request that was refused after its redirect URI had been checked, so the refusal is
 * sent to the client in the fragment of the redirect URI. It is marked authenticated only so the authorization endpoint
 * hands it to the response handler instead of continuing the chain.
 */
public class LegacyImplicitErrorToken extends AbstractAuthenticationToken {

    /** Serial version. */
    private static final long serialVersionUID = 1L;

    /** Error code. */
    private final String error;

    /** Human readable description of the error, {@code null} when there is none. */
    private final String description;

    /** The registered redirect URI the error is sent to. */
    private final String redirectUri;

    /** State of the request, {@code null} when it had none. */
    private final String state;

    /**
     * Creates the result.
     *
     * @param error       error code.
     * @param description description of the error, may be {@code null}.
     * @param redirectUri the registered redirect URI.
     * @param state       state of the request, may be {@code null}.
     */
    public LegacyImplicitErrorToken(final String error, final String description, final String redirectUri,
            final String state) {
        super(List.of());
        this.error = error;
        this.description = description;
        this.redirectUri = redirectUri;
        this.state = state;
        setAuthenticated(true);
    }

    /**
     * Returns the error code.
     *
     * @return the code.
     */
    public String getError() {
        return error;
    }

    /**
     * Returns the description of the error.
     *
     * @return the description, {@code null} when there is none.
     */
    public String getDescription() {
        return description;
    }

    /**
     * Returns the redirect URI the error is sent to.
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
     * Returns the principal, which a refusal has none of.
     *
     * @return the error code, so the token has a name.
     */
    @Override
    public Object getPrincipal() {
        return error;
    }
}
