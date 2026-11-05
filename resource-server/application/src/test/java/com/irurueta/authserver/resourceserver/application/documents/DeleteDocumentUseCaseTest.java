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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.resourceserver.domain.documents.Document;
import com.irurueta.authserver.resourceserver.domain.documents.DocumentRepository;
import java.util.Optional;
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

    /** Owner of the document. */
    private static final String OWNER = "alice";

    /** A caller who does not own the document. */
    private static final String OTHER = "mallory";

    /** Mocked port. */
    @Mock
    private DocumentRepository documentRepository;

    /** Subject under test. */
    @InjectMocks
    private DeleteDocumentUseCase useCase;

    /** The owner deletes their document. */
    @Test
    void execute_whenCallerOwnsTheDocument_deletesIt() {
        when(documentRepository.findById(ID)).thenReturn(Optional.of(document()));
        when(documentRepository.deleteById(ID)).thenReturn(true);

        assertTrue(useCase.execute(ID, OWNER, false));
    }

    /** An administrator deletes someone else's document. */
    @Test
    void execute_whenCallerIsAdministrator_deletesAnyDocument() {
        when(documentRepository.findById(ID)).thenReturn(Optional.of(document()));
        when(documentRepository.deleteById(ID)).thenReturn(true);

        assertTrue(useCase.execute(ID, OTHER, true));
    }

    /** Someone else's document is left alone and reported like a missing one. */
    @Test
    void execute_whenCallerDoesNotOwnTheDocument_keepsItAndReturnsFalse() {
        when(documentRepository.findById(ID)).thenReturn(Optional.of(document()));

        assertFalse(useCase.execute(ID, OTHER, false));

        verify(documentRepository, never()).deleteById(ID);
    }

    /** A missing document reports false. */
    @Test
    void execute_whenDocumentIsMissing_returnsFalse() {
        when(documentRepository.findById(ID)).thenReturn(Optional.empty());

        assertFalse(useCase.execute(ID, OWNER, true));

        verify(documentRepository, never()).deleteById(ID);
    }

    /** A document deleted concurrently, between the look-up and the deletion, reports false. */
    @Test
    void execute_whenDocumentVanishesBeforeTheDeletion_returnsFalse() {
        when(documentRepository.findById(ID)).thenReturn(Optional.of(document()));
        when(documentRepository.deleteById(ID)).thenReturn(false);

        assertFalse(useCase.execute(ID, OWNER, false));
    }

    /**
     * Builds the document of {@link #OWNER}.
     *
     * @return the document.
     */
    private static Document document() {
        return new Document(ID, OWNER, "Title", "Content");
    }
}
