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

import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

/**
 * Creates the JSON mapper that serializes the attributes and token claims stored with each authorization.
 *
 * <p>It is the framework's own mapper with {@link Long} added to the allowed types, because claims such as
 * {@code auth_time} are numeric dates that the polymorphic type validator would otherwise reject when an
 * authorization is read back.
 */
@Component
public class AuthorizationJsonMapperFactory {

    /**
     * Creates the mapper.
     *
     * @return a mapper with the framework's security modules and {@link Long} allowed.
     */
    public JsonMapper create() {
        final var validator = BasicPolymorphicTypeValidator.builder().allowIfSubType(Long.class);
        return JsonMapper.builder()
                .addModules(SecurityJacksonModules.getModules(getClass().getClassLoader(), validator))
                .build();
    }
}
