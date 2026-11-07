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

package com.irurueta.authserver.authorization.application.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PasskeyProperties}. The default name is applied by the binder from the {@code @DefaultValue}
 * annotation; the startup binding is covered by the integration tests.
 */
class PasskeyPropertiesTest {

    /** Relying party name. */
    private static final String NAME = "Acme";

    /** Relying party id. */
    private static final String RP_ID = "example.com";

    /** Allowed origin. */
    private static final String ORIGIN = "https://example.com";

    /**
     * Verifies that valid values are kept and the origins are copied.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThemAndCopiesOrigins() {
        final var origins = new ArrayList<>(List.of(ORIGIN));

        final var properties = new PasskeyProperties(NAME, RP_ID, origins);
        origins.add("https://other.example.com");

        assertEquals(NAME, properties.rpName());
        assertEquals(RP_ID, properties.rpId());
        assertEquals(List.of(ORIGIN), properties.allowedOrigins());
    }

    /**
     * Verifies that a missing or blank name is rejected.
     */
    @Test
    void constructor_whenNameIsBlank_throwsIllegalArgumentException() {
        final var origins = List.of(ORIGIN);

        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(null, RP_ID, origins));
        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(" ", RP_ID, origins));
    }

    /**
     * Verifies that a missing or blank relying party id is rejected.
     */
    @Test
    void constructor_whenRpIdIsBlank_throwsIllegalArgumentException() {
        final var origins = List.of(ORIGIN);

        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(NAME, null, origins));
        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(NAME, "", origins));
    }

    /**
     * Verifies that missing, empty or blank origins are rejected.
     */
    @Test
    void constructor_whenOriginsAreMissingOrBlank_throwsIllegalArgumentException() {
        final var withNull = Arrays.asList(ORIGIN, null);

        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(NAME, RP_ID, null));
        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(NAME, RP_ID, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(NAME, RP_ID, List.of(" ")));
        assertThrows(IllegalArgumentException.class, () -> new PasskeyProperties(NAME, RP_ID, withNull));
    }
}
