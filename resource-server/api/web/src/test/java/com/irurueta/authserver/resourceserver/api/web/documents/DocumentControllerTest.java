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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.resourceserver.api.web.v1.generated.model.DocumentResponse;
import com.irurueta.authserver.resourceserver.application.documents.DeleteDocumentUseCase;
import com.irurueta.authserver.resourceserver.application.documents.ListDocumentsUseCase;
import com.irurueta.authserver.resourceserver.domain.documents.Document;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

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

    /** Real mapper onto the generated DTO, spied so the controller is wired with it. */
    @Spy
    private DocumentDtoMapper documentDtoMapper = new DocumentDtoMapper();

    /** Subject under test. */
    @InjectMocks
    private DocumentController controller;

    /** Clears the caller set by a test, so it never leaks into another one. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /** A regular caller only sees their own documents. */
    @Test
    void list_whenCallerIsNotAdministrator_listsOwnDocuments() {
        when(listDocumentsUseCase.listOwn(SUBJECT)).thenReturn(List.of(new Document(ID, SUBJECT, "T", "C")));

        signIn("SCOPE_documents.read");

        final var response = controller.listDocuments();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(List.of(new DocumentResponse(ID, SUBJECT, "T", "C")), response.getBody());
        verifyNoInteractions(deleteDocumentUseCase);
    }

    /** An administrator sees every document. */
    @Test
    void list_whenCallerIsAdministrator_listsAllDocuments() {
        when(listDocumentsUseCase.listAll()).thenReturn(List.of(new Document(ID, "bob", "T", "C")));

        signIn("ROLE_ADMIN");

        final var response = controller.listDocuments();

        assertEquals(List.of(new DocumentResponse(ID, "bob", "T", "C")), response.getBody());
    }

    /** Deleting a document passes the caller and whether they are an administrator, and answers 204. */
    @Test
    void delete_whenDocumentIsDeleted_returnsNoContent() {
        when(deleteDocumentUseCase.execute(ID, SUBJECT, false)).thenReturn(true);

        signIn("SCOPE_documents.delete");

        assertEquals(HttpStatus.NO_CONTENT, controller.deleteDocument(ID).getStatusCode());
        verify(deleteDocumentUseCase).execute(ID, SUBJECT, false);
    }

    /** An administrator is passed as such. */
    @Test
    void delete_whenCallerIsAdministrator_passesTheAdministratorFlag() {
        when(deleteDocumentUseCase.execute(ID, SUBJECT, true)).thenReturn(true);

        signIn("ROLE_ADMIN");

        assertEquals(HttpStatus.NO_CONTENT, controller.deleteDocument(ID).getStatusCode());
    }

    /** A missing document, or someone else's, answers 404. */
    @Test
    void delete_whenDocumentIsMissingOrNotOwned_returnsNotFound() {
        when(deleteDocumentUseCase.execute(ID, SUBJECT, false)).thenReturn(false);

        signIn("SCOPE_documents.delete");

        assertEquals(HttpStatus.NOT_FOUND, controller.deleteDocument(ID).getStatusCode());
    }

    /** Without an authenticated caller nothing is listed: the request is rejected as unauthenticated. */
    @Test
    void listDocuments_whenNobodyIsAuthenticated_throwsAuthenticationCredentialsNotFoundException() {
        assertThrows(AuthenticationCredentialsNotFoundException.class, controller::listDocuments);
        verifyNoInteractions(listDocumentsUseCase);
    }

    /**
     * Authenticates the caller in the security context, as the bearer token filter does.
     *
     * @param authorities authorities of the caller.
     */
    private static void signIn(final String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(SUBJECT, null,
                authorities));
    }
}
