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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.model.DocumentResponse;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DocumentMapper}.
 */
class DocumentMapperTest {

    /** Mapper under test. */
    private final DocumentMapper mapper = new DocumentMapper();

    /**
     * Verifies that the id, owner and title are mapped and the content, which the domain does not hold, is dropped.
     */
    @Test
    void toDomain_whenResponseIsValid_mapsIt() {
        final var response = new DocumentResponse().id("1").owner("alice").title("Title").content("Body");

        assertEquals(new Document("1", "alice", "Title"), mapper.toDomain(response));
    }

    /**
     * Verifies that a document that breaks the domain invariants is refused.
     */
    @Test
    void toDomain_whenResponseHasNoOwner_throwsIllegalArgumentException() {
        final var response = new DocumentResponse().id("1").title("Title");

        assertThrows(IllegalArgumentException.class, () -> mapper.toDomain(response));
    }
}
