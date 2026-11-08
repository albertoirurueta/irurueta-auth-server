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
package com.irurueta.authserver.authorization.api.web.clientauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link MtlsProperties}. */
class MtlsPropertiesTest {

    /** A path used by the tests. */
    private static final String PATH = "/etc/ca.pem";

    /** The paths are kept. */
    @Test
    void constructor_whenPathsAreGiven_keepsThem() {
        assertEquals(List.of(PATH), new MtlsProperties(List.of(PATH)).trustedAuthorities());
    }

    /** No list means no authority. */
    @Test
    void constructor_whenListIsNull_hasNoAuthority() {
        assertTrue(new MtlsProperties(null).trustedAuthorities().isEmpty());
    }

    /** A blank path is refused. */
    @Test
    void constructor_whenAPathIsBlank_throwsIllegalArgumentException() {
        final var paths = List.of(PATH, " ");

        assertThrows(IllegalArgumentException.class, () -> new MtlsProperties(paths));
    }

    /** The list is copied, so a later change of the original is not seen. */
    @Test
    void constructor_whenListIsChangedAfterwards_isNotAffected() {
        final var paths = new ArrayList<>(List.of(PATH));
        final var properties = new MtlsProperties(paths);

        paths.add("other");

        assertEquals(List.of(PATH), properties.trustedAuthorities());
    }
}
