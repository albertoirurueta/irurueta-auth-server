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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link IdentityDtoMapper}.
 */
class IdentityDtoMapperTest {

    /** Link instant. */
    private static final Instant LINKED = Instant.parse("2026-01-01T00:00:00Z");

    /** Last sign-in instant. */
    private static final Instant LAST_LOGIN = Instant.parse("2026-02-01T00:00:00Z");

    /** Mapper under test. */
    private final IdentityDtoMapper mapper = new IdentityDtoMapper();

    /**
     * Verifies that every public field is copied, the provider as the contract's value, and that the subject and the
     * account are not part of the answer.
     */
    @Test
    void toResponse_whenIdentityWasUsed_copiesItsPublicFields() {
        final var id = UUID.randomUUID();

        final var response = mapper.toResponse(new FederatedIdentity(id, UUID.randomUUID(), IdentityProvider.GITHUB,
                "subject", "alice@example.org", LINKED, LAST_LOGIN));

        assertEquals(id, response.id());
        assertEquals("github", response.provider().getValue());
        assertEquals("alice@example.org", response.email());
        assertEquals(LINKED, response.linkedAt());
        assertEquals(LAST_LOGIN, response.lastLoginAt());
    }

    /**
     * Verifies that an identity without an address or a sign-in has neither.
     */
    @Test
    void toResponse_whenIdentityHasNoEmailAndWasNeverUsed_hasNeither() {
        final var response = mapper.toResponse(new FederatedIdentity(UUID.randomUUID(), UUID.randomUUID(),
                IdentityProvider.GOOGLE, "subject", null, LINKED, null));

        assertNull(response.email());
        assertNull(response.lastLoginAt());
    }

    /**
     * Verifies that several identities are mapped in order.
     */
    @Test
    void toResponses_whenSeveralIdentities_keepsTheirOrder() {
        final var responses = mapper.toResponses(List.of(
                new FederatedIdentity(UUID.randomUUID(), UUID.randomUUID(), IdentityProvider.GOOGLE, "a", null,
                        LINKED, null),
                new FederatedIdentity(UUID.randomUUID(), UUID.randomUUID(), IdentityProvider.APPLE, "b", null,
                        LINKED, null)));

        assertEquals(List.of("google", "apple"), responses.stream().map(r -> r.provider().getValue()).toList());
    }
}
