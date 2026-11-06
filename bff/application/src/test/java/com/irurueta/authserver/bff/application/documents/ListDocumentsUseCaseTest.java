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

package com.irurueta.authserver.bff.application.documents;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.bff.domain.documents.Document;
import com.irurueta.authserver.bff.domain.documents.DocumentGateway;
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
        final var documents = List.of(new Document("1", "alice", "Title", "Body"));
        when(documentGateway.list()).thenReturn(documents);

        assertSame(documents, useCase.execute());
    }
}
