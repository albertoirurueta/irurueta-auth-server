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

package com.irurueta.authserver.authorization.api.web.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.authorization.api.web.v1.generated.model.SigningKeyResponse;
import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SigningKeyDtoMapper}.
 */
class SigningKeyDtoMapperTest {

    /** Private half of the test keys, which must never be mapped. */
    private static final String PRIVATE_PART = "private-part";

    /** Creation instant of the test keys. */
    private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");

    /** Retirement instant of the retired test key. */
    private static final Instant RETIRED = Instant.parse("2026-02-01T00:00:00Z");

    /** Mapper under test. */
    private final SigningKeyDtoMapper mapper = new SigningKeyDtoMapper();

    /**
     * Verifies that the public view carries every public field and never the private half.
     */
    @Test
    void toResponse_whenKeyIsRetired_copiesThePublicFieldsOnly() {
        final var key = new SigningKey("kid-1", "RS256", "{\"kty\":\"RSA\"}", PRIVATE_PART, SigningKeyStatus.RETIRED,
                CREATED, CREATED, RETIRED);

        final var response = mapper.toResponse(key);

        assertEquals(new SigningKeyResponse("kid-1", "RS256", "RETIRED", CREATED, CREATED, RETIRED,
                "{\"kty\":\"RSA\"}"), response);
        assertFalse(response.toString().contains(PRIVATE_PART));
    }

    /**
     * Verifies that a key that never signed has no activation nor retirement instant.
     */
    @Test
    void toResponse_whenKeyIsNext_hasNoActivationNorRetirement() {
        final var key = new SigningKey("kid-2", "RS256", "{}", PRIVATE_PART, SigningKeyStatus.NEXT, CREATED, null,
                null);

        final var response = mapper.toResponse(key);

        assertEquals("NEXT", response.status());
        assertNull(response.activatedAt());
        assertNull(response.retiredAt());
    }

    /**
     * Verifies that several keys keep their order.
     */
    @Test
    void toResponses_whenKeysAreGiven_keepsTheirOrder() {
        final var active = new SigningKey("kid-1", "RS256", "{}", PRIVATE_PART, SigningKeyStatus.ACTIVE, CREATED,
                CREATED, null);
        final var next = new SigningKey("kid-2", "RS256", "{}", PRIVATE_PART, SigningKeyStatus.NEXT, CREATED, null,
                null);

        final var responses = mapper.toResponses(List.of(active, next));

        assertEquals(List.of("kid-1", "kid-2"), responses.stream().map(SigningKeyResponse::kid).toList());
    }
}
