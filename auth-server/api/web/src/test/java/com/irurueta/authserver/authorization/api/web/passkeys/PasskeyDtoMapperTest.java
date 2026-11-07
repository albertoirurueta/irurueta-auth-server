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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PasskeyDtoMapper}.
 */
class PasskeyDtoMapperTest {

    /** Signature counter of the passkey. */
    private static final long SIGNATURE_COUNT = 7L;

    /** Creation instant. */
    private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");

    /** Last use instant. */
    private static final Instant LAST_USED = Instant.parse("2026-02-01T00:00:00Z");

    /** Mapper under test. */
    private final PasskeyDtoMapper mapper = new PasskeyDtoMapper();

    /**
     * Verifies that every public field is copied and the user handle is left out.
     */
    @Test
    void toResponse_whenPasskeyWasUsed_copiesItsPublicFields() {
        final var response = mapper.toResponse(
                new Passkey("cred-1", "handle", "Laptop", CREATED, LAST_USED, SIGNATURE_COUNT, true, false));

        assertEquals("cred-1", response.id());
        assertEquals("Laptop", response.label());
        assertEquals(CREATED, response.createdAt());
        assertEquals(LAST_USED, response.lastUsedAt());
        assertEquals(SIGNATURE_COUNT, response.signatureCount());
        assertTrue(response.backupEligible());
        assertEquals(false, response.backedUp());
    }

    /**
     * Verifies that a passkey that never signed in has no last use.
     */
    @Test
    void toResponse_whenPasskeyWasNeverUsed_hasNoLastUse() {
        final var response = mapper.toResponse(new Passkey("cred-1", "handle", "Laptop", CREATED, null, 0L, false,
                false));

        assertNull(response.lastUsedAt());
    }

    /**
     * Verifies that several passkeys are mapped in order.
     */
    @Test
    void toResponses_whenSeveralPasskeys_keepsTheirOrder() {
        final var responses = mapper.toResponses(List.of(
                new Passkey("a", "handle", "First", CREATED, null, 0L, false, false),
                new Passkey("b", "handle", "Second", CREATED, null, 0L, false, false)));

        assertEquals(List.of("a", "b"), responses.stream().map(response -> response.id()).toList());
    }
}
