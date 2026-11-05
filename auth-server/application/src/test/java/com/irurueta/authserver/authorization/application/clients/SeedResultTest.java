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

package com.irurueta.authserver.authorization.application.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SeedResult}.
 */
class SeedResultTest {

    /**
     * The lists are copied.
     */
    @Test
    void constructor_whenListIsModifiedLater_keepsItsCopy() {
        final var created = new ArrayList<>(List.of("a"));

        final var result = new SeedResult(created, List.of("b"));
        created.add("c");

        assertEquals(List.of("a"), result.created());
        assertEquals(List.of("b"), result.skipped());
    }

    /**
     * A null list is rejected.
     */
    @Test
    void constructor_whenListIsNull_throwsNullPointerException() {
        final var skipped = List.<String>of();

        assertThrows(NullPointerException.class, () -> new SeedResult(null, skipped));
    }
}
