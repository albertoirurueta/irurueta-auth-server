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

package com.irurueta.authserver.serviceclient.application.documents;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException;
import com.irurueta.authserver.serviceclient.domain.documents.DocumentGateway;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ListDocumentsUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ListDocumentsUseCaseTest {

    /** Port to the documents. */
    @Mock
    private DocumentGateway documentGateway;

    /** Use case under test. */
    @InjectMocks
    private ListDocumentsUseCase useCase;

    /** The documents of the gateway are returned as they are. */
    @Test
    void execute_whenGatewayHasDocuments_returnsThem() {
        final var documents = List.of(new Document("1", "alice", "Title"));
        when(documentGateway.listDocuments()).thenReturn(documents);

        assertSame(documents, useCase.execute());
    }

    /** A failure of the gateway reaches the caller. */
    @Test
    void execute_whenGatewayFails_propagatesDocumentAccessException() {
        final var failure = new DocumentAccessException("failure", null);
        when(documentGateway.listDocuments()).thenThrow(failure);

        assertSame(failure, assertThrows(DocumentAccessException.class, () -> useCase.execute()));
    }
}
