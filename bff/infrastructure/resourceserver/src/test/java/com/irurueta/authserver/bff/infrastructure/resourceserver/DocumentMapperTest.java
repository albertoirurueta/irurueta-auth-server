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

package com.irurueta.authserver.bff.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.bff.domain.documents.Document;
import com.irurueta.authserver.bff.infrastructure.resourceserver.v1.generated.model.DocumentResponse;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DocumentMapper}.
 */
class DocumentMapperTest {

    /** Mapper under test. */
    private final DocumentMapper mapper = new DocumentMapper();

    /**
     * Verifies that every field of the generated model reaches the domain document.
     */
    @Test
    void toDomain_whenResponseIsComplete_mapsEveryField() {
        final var response = new DocumentResponse().id("1").owner("alice").title("Title").content("Body");

        assertEquals(new Document("1", "alice", "Title", "Body"), mapper.toDomain(response));
    }

    /**
     * Verifies that a document breaking the domain invariants is rejected.
     */
    @Test
    void toDomain_whenTitleIsMissing_throwsIllegalArgumentException() {
        final var response = new DocumentResponse().id("1").owner("alice").content("Body");

        assertThrows(IllegalArgumentException.class, () -> mapper.toDomain(response));
    }
}
