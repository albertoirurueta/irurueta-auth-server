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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.resourceserver.application.documents.DeleteDocumentUseCase;
import com.irurueta.authserver.resourceserver.application.documents.ListDocumentsUseCase;
import com.irurueta.authserver.resourceserver.domain.documents.Document;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;

/**
 * Unit tests for {@link DocumentController}.
 */
@ExtendWith(MockitoExtension.class)
class DocumentControllerTest {

    /** Subject of the caller. */
    private static final String SUBJECT = "alice";

    /** Identifier of a document. */
    private static final String ID = "d1";

    /** Mocked list use case. */
    @Mock
    private ListDocumentsUseCase listDocumentsUseCase;

    /** Mocked delete use case. */
    @Mock
    private DeleteDocumentUseCase deleteDocumentUseCase;

    /** Subject under test. */
    @InjectMocks
    private DocumentController controller;

    /** A regular caller only sees their own documents. */
    @Test
    void list_whenCallerIsNotAdministrator_listsOwnDocuments() {
        when(listDocumentsUseCase.listOwn(SUBJECT)).thenReturn(List.of(new Document(ID, SUBJECT, "T", "C")));

        final var response = controller.list(new TestingAuthenticationToken(SUBJECT, null, "SCOPE_documents.read"));

        assertEquals(List.of(new DocumentResponse(ID, SUBJECT, "T", "C")), response);
        verifyNoInteractions(deleteDocumentUseCase);
    }

    /** An administrator sees every document. */
    @Test
    void list_whenCallerIsAdministrator_listsAllDocuments() {
        when(listDocumentsUseCase.listAll()).thenReturn(List.of(new Document(ID, "bob", "T", "C")));

        final var response = controller.list(new TestingAuthenticationToken(SUBJECT, null, "ROLE_ADMIN"));

        assertEquals(List.of(new DocumentResponse(ID, "bob", "T", "C")), response);
    }

    /** Deleting a document passes the caller and whether they are an administrator, and answers 204. */
    @Test
    void delete_whenDocumentIsDeleted_returnsNoContent() {
        when(deleteDocumentUseCase.execute(ID, SUBJECT, false)).thenReturn(true);

        assertEquals(HttpStatus.NO_CONTENT, controller.delete(ID, caller("SCOPE_documents.delete")).getStatusCode());
        verify(deleteDocumentUseCase).execute(ID, SUBJECT, false);
    }

    /** An administrator is passed as such. */
    @Test
    void delete_whenCallerIsAdministrator_passesTheAdministratorFlag() {
        when(deleteDocumentUseCase.execute(ID, SUBJECT, true)).thenReturn(true);

        assertEquals(HttpStatus.NO_CONTENT, controller.delete(ID, caller("ROLE_ADMIN")).getStatusCode());
    }

    /** A missing document, or someone else's, answers 404. */
    @Test
    void delete_whenDocumentIsMissingOrNotOwned_returnsNotFound() {
        when(deleteDocumentUseCase.execute(ID, SUBJECT, false)).thenReturn(false);

        assertEquals(HttpStatus.NOT_FOUND, controller.delete(ID, caller("SCOPE_documents.delete")).getStatusCode());
    }

    /**
     * Builds an authenticated caller.
     *
     * @param authorities authorities of the caller.
     * @return the caller.
     */
    private static TestingAuthenticationToken caller(final String... authorities) {
        return new TestingAuthenticationToken(SUBJECT, null, authorities);
    }
}
