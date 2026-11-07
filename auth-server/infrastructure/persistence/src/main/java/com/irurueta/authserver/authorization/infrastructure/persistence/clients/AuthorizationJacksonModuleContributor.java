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
package com.irurueta.authserver.authorization.infrastructure.persistence.clients;

import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Extension point that adds a Jackson module to the mapper of the stored authorizations
 * ({@link AuthorizationJsonMapperFactory}), for a feature whose authentication or attribute types the framework's
 * security modules do not cover (for example the passkeys, whose module Spring Security leaves out of
 * {@code SecurityJacksonModules}). Every bean of this type is applied; no shared file is edited.
 *
 * <p>It is deliberately not a plain {@link JacksonModule} bean: Spring Boot adds every such bean to the
 * application-wide {@code JsonMapper}, which would widen the polymorphic typing of every JSON answer of the
 * application, while the module only belongs to the mapper of the stored authorizations. It also needs the type
 * validator of that mapper, which only the factory has.
 */
@FunctionalInterface
public interface AuthorizationJacksonModuleContributor {

    /**
     * Creates the module and allows, in the validator, the types it (de)serializes polymorphically. It is called
     * before the framework's modules are created, while the validator can still be configured.
     *
     * @param validator builder of the polymorphic type validator of the authorization mapper.
     * @return the module to add.
     */
    JacksonModule module(BasicPolymorphicTypeValidator.Builder validator);
}
