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
package com.irurueta.authserver.authorization.domain.social;

import java.util.Arrays;
import java.util.Optional;

/**
 * External identity providers an account can be linked to. The identifier is the registration id of the provider in
 * the configuration ({@code authserver.social.providers.<id>}) and the value stored with every link.
 */
public enum IdentityProvider {

    /** Google, an OpenID Connect provider. */
    GOOGLE("google"),

    /** Microsoft Entra ID, an OpenID Connect provider with a multi-tenant issuer. */
    MICROSOFT("microsoft"),

    /** Sign in with Apple, an OpenID Connect provider whose client secret is a signed JWT. */
    APPLE("apple"),

    /** GitHub, a plain OAuth 2.0 provider. */
    GITHUB("github");

    /** Registration id of the provider, in lower case. */
    private final String id;

    /**
     * Creates a provider.
     *
     * @param id registration id of the provider.
     */
    IdentityProvider(final String id) {
        this.id = id;
    }

    /**
     * Returns the registration id of the provider.
     *
     * @return the lower case registration id.
     */
    public String id() {
        return id;
    }

    /**
     * Finds a provider by its registration id.
     *
     * @param id registration id, compared exactly.
     * @return the provider, or an empty optional when the id is {@code null} or unknown.
     */
    public static Optional<IdentityProvider> fromId(final String id) {
        return Arrays.stream(values()).filter(provider -> provider.id.equals(id)).findFirst();
    }
}
