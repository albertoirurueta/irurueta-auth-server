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

package com.irurueta.authserver.serviceclient.domain.documents;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link Document}.
 */
class DocumentTest {

    /** Identifier used by the tests. */
    private static final String ID = "doc-1";

    /** Owner used by the tests. */
    private static final String OWNER = "alice";

    /** Title used by the tests. */
    private static final String TITLE = "Title";

    /** A valid document keeps its components. */
    @Test
    void constructor_whenValid_keepsComponents() {
        final var document = new Document(ID, OWNER, TITLE);

        assertEquals(ID, document.id());
        assertEquals(OWNER, document.owner());
        assertEquals(TITLE, document.title());
    }

    /** A null id is rejected. */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        final var error = assertThrows(IllegalArgumentException.class, () -> new Document(null, OWNER, TITLE));

        assertEquals("id is required", error.getMessage());
    }

    /** A blank owner is rejected. */
    @Test
    void constructor_whenOwnerIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Document(ID, " ", TITLE));
    }

    /** A null title is rejected. */
    @Test
    void constructor_whenTitleIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new Document(ID, OWNER, null));
    }

    /** Two documents with the same components are equal. */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new Document(ID, OWNER, TITLE);
        final var second = new Document(ID, OWNER, TITLE);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }
}
