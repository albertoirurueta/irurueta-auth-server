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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.resourceserver.domain.documents.Document;
import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@link ListDocumentsUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ListDocumentsUseCaseTest {

    /** Owner used by the tests. */
    private static final String OWNER = "alice";

    /** Mocked port. */
    @Mock
    private DocumentRepository documentRepository;

    /** Subject under test. */
    @InjectMocks
    private ListDocumentsUseCase useCase;

    /** The documents of the owner come from the port untouched. */
    @Test
    void listOwn_whenOwnerHasDocuments_returnsPortResult() {
        final var documents = List.of(new Document("d1", OWNER, "T", "C"));
        when(documentRepository.findByOwner(OWNER)).thenReturn(documents);

        assertSame(documents, useCase.listOwn(OWNER));
    }

    /** All documents come from the port untouched. */
    @Test
    void listAll_whenDocumentsExist_returnsPortResult() {
        final var documents = List.of(new Document("d1", OWNER, "T", "C"));
        when(documentRepository.findAll()).thenReturn(documents);

        assertSame(documents, useCase.listAll());
    }
}
