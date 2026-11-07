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
package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import com.irurueta.authserver.authorization.infrastructure.persistence.clients.AuthorizationJacksonModuleContributor;
import org.springframework.security.web.webauthn.jackson.WebauthnJacksonModule;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Adds the module of the passkeys to the mapper of the stored authorizations. {@code SecurityJacksonModules} leaves
 * it out on purpose, but the principal of an authorization started with a passkey is a {@code WebAuthnAuthentication}
 * holding a user entity, and without the module (which allows exactly those two types) the authorization could be
 * written but never read back, so no token would be issued after a passkey sign-in.
 */
@Component
public class WebauthnJacksonModuleContributor implements AuthorizationJacksonModuleContributor {

    // tag::passkeys-json-mapper[]
    /**
     * Creates the module of the passkeys and allows its types in the validator.
     *
     * @param validator builder of the polymorphic type validator of the authorization mapper.
     * @return the configured module.
     */
    @Override
    public JacksonModule module(final BasicPolymorphicTypeValidator.Builder validator) {
        final var webauthn = new WebauthnJacksonModule();
        webauthn.configurePolymorphicTypeValidator(validator);
        return webauthn;
    }
    // end::passkeys-json-mapper[]
}
