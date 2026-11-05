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

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SigningKeyResponse}.
 */
class SigningKeyResponseTest {

    /** Creation instant used by the tests. */
    private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");

    /**
     * The mapping copies the public data and drops the private half.
     */
    @Test
    void from_whenKeyIsNext_mapsPublicFieldsOnly() {
        final var key = new SigningKey("kid-1", "RS256", "{\"kty\":\"RSA\"}", "private-part", SigningKeyStatus.NEXT,
                CREATED, null, null);

        final var response = SigningKeyResponse.from(key);

        assertEquals("kid-1", response.kid());
        assertEquals("RS256", response.alg());
        assertEquals("NEXT", response.status());
        assertEquals(CREATED, response.createdAt());
        assertNull(response.activatedAt());
        assertNull(response.retiredAt());
        assertEquals("{\"kty\":\"RSA\"}", response.publicJwk());
        assertFalse(response.toString().contains("private-part"));
    }
}
