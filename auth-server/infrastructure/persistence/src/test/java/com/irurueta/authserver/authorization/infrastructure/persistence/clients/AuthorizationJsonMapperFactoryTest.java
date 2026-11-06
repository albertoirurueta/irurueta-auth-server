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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Unit tests of {@link AuthorizationJsonMapperFactory}.
 */
class AuthorizationJsonMapperFactoryTest {

    /** Epoch second used as a numeric claim. */
    private static final long EPOCH_SECOND = 1_767_261_600L;

    /** Factory under test. */
    private final AuthorizationJsonMapperFactory factory = new AuthorizationJsonMapperFactory();

    /**
     * Verifies that a map holding a long survives a round trip with default typing.
     */
    @Test
    void create_whenMapHoldsALong_roundTripsIt() {
        final JsonMapper mapper = factory.create();
        final var type = new TypeReference<Map<String, Object>>() { };
        final var claims = new HashMap<String, Object>();
        claims.put("auth_time", EPOCH_SECOND);
        final var json = mapper.writerFor(type).writeValueAsString(claims);
        final var read = mapper.readValue(json, type);
        assertEquals(EPOCH_SECOND, ((Number) read.get("auth_time")).longValue());
    }
}
