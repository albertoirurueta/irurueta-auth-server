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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import com.irurueta.authserver.authorization.infrastructure.persistence.clients.AuthorizationJacksonModuleContributor;
import org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Adds the module of the OAuth 2.0 client to the mapper of the stored authorizations. The principal of an authorization
 * started with an external provider is an {@code OAuth2AuthenticationToken} holding an {@code OAuth2User} or an
 * {@code OidcUser} with its authorities and, for OpenID Connect, its ID token and user info. Without the module, which
 * allows exactly those types, the authorization could be written but never read back, so no token would be issued
 * after a social sign-in.
 */
@Component
public class FederatedJacksonModuleContributor implements AuthorizationJacksonModuleContributor {

    // tag::social-json-mapper[]
    /**
     * Creates the module of the OAuth 2.0 client and allows its types in the validator.
     *
     * @param validator builder of the polymorphic type validator of the authorization mapper.
     * @return the configured module.
     */
    @Override
    public JacksonModule module(final BasicPolymorphicTypeValidator.Builder validator) {
        final var oauth2Client = new OAuth2ClientJacksonModule();
        oauth2Client.configurePolymorphicTypeValidator(validator);
        return oauth2Client;
    }
    // end::social-json-mapper[]
}
