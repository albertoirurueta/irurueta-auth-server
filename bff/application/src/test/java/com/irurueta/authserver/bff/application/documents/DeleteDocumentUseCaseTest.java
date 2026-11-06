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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import com.irurueta.authserver.bff.domain.documents.DocumentGateway;
import com.irurueta.authserver.bff.domain.documents.DocumentNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link DeleteDocumentUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class DeleteDocumentUseCaseTest {

    /** Identifier of the document. */
    private static final String ID = "7";

    /** Port to the documents. */
    @Mock
    private DocumentGateway documentGateway;

    /** Use case under test. */
    @InjectMocks
    private DeleteDocumentUseCase useCase;

    /** The deletion is delegated to the gateway. */
    @Test
    void execute_whenCalled_deletesThroughTheGateway() {
        useCase.execute(ID);

        verify(documentGateway).deleteById(ID);
    }

    /** A failure of the gateway reaches the caller unchanged. */
    @Test
    void execute_whenDocumentIsMissing_propagatesTheFailure() {
        final var failure = new DocumentNotFoundException("missing", null);
        doThrow(failure).when(documentGateway).deleteById(ID);

        assertSame(failure, assertThrows(DocumentNotFoundException.class, () -> useCase.execute(ID)));
    }
}
