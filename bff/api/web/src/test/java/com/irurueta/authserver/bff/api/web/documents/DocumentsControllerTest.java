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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.bff.api.web.v1.generated.model.DocumentResponse;
import com.irurueta.authserver.bff.application.documents.DeleteDocumentUseCase;
import com.irurueta.authserver.bff.application.documents.ListDocumentsUseCase;
import com.irurueta.authserver.bff.domain.documents.Document;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

/**
 * Unit tests of {@link DocumentsController}.
 */
@ExtendWith(MockitoExtension.class)
class DocumentsControllerTest {

    /** Identifier of the document. */
    private static final String ID = "7";

    /** Lists the documents. */
    @Mock
    private ListDocumentsUseCase listDocumentsUseCase;

    /** Deletes a document. */
    @Mock
    private DeleteDocumentUseCase deleteDocumentUseCase;

    /** Maps the documents; the real one. */
    @Spy
    private DocumentDtoMapper documentDtoMapper;

    /** Controller under test. */
    @InjectMocks
    private DocumentsController controller;

    /**
     * Verifies that the documents of the use case are answered as DTOs.
     */
    @Test
    void listDocuments_whenUserHasDocuments_answersThemAsDtos() {
        when(listDocumentsUseCase.execute()).thenReturn(List.of(new Document(ID, "alice", "Title", "Body")));

        final var response = controller.listDocuments();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(List.of(new DocumentResponse(ID, "alice", "Title", "Body")), response.getBody());
    }

    /**
     * Verifies that a deletion runs the use case and answers 204 without a body.
     */
    @Test
    void deleteDocument_whenDeleted_answersNoContent() {
        final var response = controller.deleteDocument(ID);

        verify(deleteDocumentUseCase).execute(ID);
        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        assertNull(response.getBody());
    }
}
