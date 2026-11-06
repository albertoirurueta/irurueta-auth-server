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

package com.irurueta.authserver.bff.api.web.documents;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.bff.api.web.v1.generated.model.DocumentResponse;
import com.irurueta.authserver.bff.domain.documents.Document;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DocumentDtoMapper}.
 */
class DocumentDtoMapperTest {

    /** Mapper under test. */
    private final DocumentDtoMapper mapper = new DocumentDtoMapper();

    /**
     * Verifies that every field of the domain document reaches the DTO.
     */
    @Test
    void toResponse_whenCalled_mapsEveryField() {
        assertEquals(new DocumentResponse("1", "alice", "Title", "Body"),
                mapper.toResponse(new Document("1", "alice", "Title", "Body")));
    }
}
