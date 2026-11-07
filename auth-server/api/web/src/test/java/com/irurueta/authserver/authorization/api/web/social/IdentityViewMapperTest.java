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

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link IdentityViewMapper}.
 */
class IdentityViewMapperTest {

    /** Instant the identity was linked. */
    private static final Instant LINKED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Mapper under test. */
    private final IdentityViewMapper mapper = new IdentityViewMapper();

    /**
     * Verifies that the provider, the address and the instant are shown, in order.
     */
    @Test
    void toViews_whenCalled_mapsEachIdentityInOrder() {
        final var userId = UUID.randomUUID();
        final var google = new FederatedIdentity(UUID.randomUUID(), userId, IdentityProvider.GOOGLE, "s1",
                "alice@example.org", LINKED_AT, null);
        final var github = new FederatedIdentity(UUID.randomUUID(), userId, IdentityProvider.GITHUB, "s2", null,
                LINKED_AT, null);

        assertEquals(List.of(new IdentityView("google", "alice@example.org", LINKED_AT),
                new IdentityView("github", null, LINKED_AT)), mapper.toViews(List.of(google, github)));
    }
}
