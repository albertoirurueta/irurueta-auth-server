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

package com.irurueta.authserver.resourceserver.application.documents;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link DeleteDocumentUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class DeleteDocumentUseCaseTest {

    /** Identifier used by the tests. */
    private static final String ID = "d1";

    /** Mocked port. */
    @Mock
    private DocumentRepository documentRepository;

    /** Subject under test. */
    @InjectMocks
    private DeleteDocumentUseCase useCase;

    /** An existing document is deleted. */
    @Test
    void execute_whenDocumentExists_returnsTrue() {
        when(documentRepository.deleteById(ID)).thenReturn(true);

        assertTrue(useCase.execute(ID));
    }

    /** A missing document reports false. */
    @Test
    void execute_whenDocumentIsMissing_returnsFalse() {
        when(documentRepository.deleteById(ID)).thenReturn(false);

        assertFalse(useCase.execute(ID));
    }
}
