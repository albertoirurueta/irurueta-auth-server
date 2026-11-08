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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import java.io.Serial;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * The user a token exchange acts for: the principal is the user's access token, which is what Spring Security's token
 * exchange provider reads as the subject token, and the name is what the authorized clients are cached under.
 */
public class SubjectTokenAuthentication extends AbstractAuthenticationToken {

    /** Serialization version. */
    @Serial
    private static final long serialVersionUID = 1L;

    /** The user's access token. */
    private final OAuth2AccessToken subjectToken;

    /** Name the exchanged token is cached under. */
    private final String name;

    /**
     * Creates the authentication.
     *
     * @param subjectToken the user's access token.
     * @param name         name the exchanged token is cached under; it must differ for different subject tokens.
     */
    public SubjectTokenAuthentication(final OAuth2AccessToken subjectToken, final String name) {
        super(List.of());
        this.subjectToken = subjectToken;
        this.name = name;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return subjectToken;
    }

    @Override
    public Object getPrincipal() {
        return subjectToken;
    }

    @Override
    public String getName() {
        return name;
    }
}
