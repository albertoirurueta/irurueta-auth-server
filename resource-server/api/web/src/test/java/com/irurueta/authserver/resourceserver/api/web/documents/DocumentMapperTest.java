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

package com.irurueta.authserver.resourceserver.api.web.documents;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.resourceserver.domain.documents.Document;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link DocumentMapper}.
 */
class DocumentMapperTest {

    /** Maps every field of a document. */
    @Test
    void toResponse_whenDocumentIsGiven_copiesEveryField() {
        final var response = DocumentMapper.toResponse(new Document("d1", "alice", "Title", "Body"));

        assertEquals(new DocumentResponse("d1", "alice", "Title", "Body"), response);
    }

    /** Keeps the order of the documents. */
    @Test
    void toResponses_whenSeveralDocuments_keepsTheirOrder() {
        final var responses = DocumentMapper.toResponses(
                List.of(new Document("d1", "alice", "A", ""), new Document("d2", "bob", "B", "")));

        assertEquals(List.of("d1", "d2"), responses.stream().map(DocumentResponse::id).toList());
    }

    /** An empty list stays empty. */
    @Test
    void toResponses_whenThereAreNoDocuments_returnsAnEmptyList() {
        assertTrue(DocumentMapper.toResponses(List.of()).isEmpty());
    }
}
