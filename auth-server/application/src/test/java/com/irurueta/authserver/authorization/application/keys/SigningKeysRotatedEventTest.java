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

package com.irurueta.authserver.authorization.application.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SigningKeysRotatedEvent}.
 */
class SigningKeysRotatedEventTest {

    /** Instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /**
     * The event exposes and compares by its instant.
     */
    @Test
    void equalsAndHashCode_whenInstantsMatch_areEqual() {
        final var first = new SigningKeysRotatedEvent(NOW);
        final var second = new SigningKeysRotatedEvent(NOW);

        assertEquals(NOW, first.rotatedAt());
        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }
}
