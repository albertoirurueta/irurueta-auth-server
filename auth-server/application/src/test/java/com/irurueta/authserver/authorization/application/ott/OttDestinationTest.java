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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OttDestination}.
 */
class OttDestinationTest {

    /** Address used by the tests. */
    private static final String ADDRESS = "someone@example.test";

    /**
     * Verifies that missing components are rejected.
     */
    @Test
    void constructor_whenAComponentIsMissing_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class, () -> new OttDestination(null, OttChannel.EMAIL, ADDRESS));
        assertThrows(IllegalArgumentException.class, () -> new OttDestination(userId, null, ADDRESS));
        assertThrows(IllegalArgumentException.class, () -> new OttDestination(userId, OttChannel.EMAIL, null));
        assertThrows(IllegalArgumentException.class, () -> new OttDestination(userId, OttChannel.EMAIL, " "));
    }

    /**
     * Verifies that the description does not leak the address.
     */
    @Test
    void toString_whenCalled_doesNotContainTheAddress() {
        final var text = new OttDestination(UUID.randomUUID(), OttChannel.EMAIL, ADDRESS).toString();

        assertFalse(text.contains(ADDRESS));
        assertTrue(text.contains("EMAIL"));
    }
}
