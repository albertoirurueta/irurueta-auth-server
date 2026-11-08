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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.model.DocumentResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;

/**
 * Unit tests of {@link DocumentCalls}.
 */
@ExtendWith(MockitoExtension.class)
class DocumentCallsTest {

    /** A token value that must never show in a message. */
    private static final String TOKEN = "eyJ-the-token";

    /** Documents client generated from the resource server's contract. */
    @Mock
    private DocumentsApi documentsApi;

    /** Maps the generated model; the real one. */
    @Spy
    private DocumentMapper documentMapper;

    /** Object under test. */
    @InjectMocks
    private DocumentCalls calls;

    /**
     * Verifies that the documents are mapped onto the domain.
     */
    @Test
    void list_whenResourceServerAnswersDocuments_mapsThem() {
        when(documentsApi.listDocuments()).thenReturn(
                List.of(new DocumentResponse().id("1").owner("alice").title("Title").content("Body")));

        assertEquals(List.of(new Document("1", "alice", "Title")), calls.list(documentsApi));
    }

    /**
     * Verifies that an answer without a body is an empty list, never {@code null}.
     */
    @Test
    void list_whenResourceServerAnswersNoBody_returnsAnEmptyList() {
        when(documentsApi.listDocuments()).thenReturn(null);

        assertTrue(calls.list(documentsApi).isEmpty());
    }

    /**
     * Verifies that a token that cannot be obtained is reported without the token or its details.
     */
    @Test
    void list_whenTokenCannotBeObtained_throwsDocumentAccessException() {
        final var failure = new ClientAuthorizationException(new OAuth2Error("invalid_client", TOKEN, null), "id");
        when(documentsApi.listDocuments()).thenThrow(failure);

        final var error = assertThrows(DocumentAccessException.class, () -> calls.list(documentsApi));

        assertSame(failure, error.getCause());
        assertFalse(error.getMessage().contains(TOKEN));
    }

    /**
     * Verifies that an error status is reported with its code.
     */
    @Test
    void list_whenResourceServerAnswersAnError_throwsDocumentAccessException() {
        final var failure = new HttpClientErrorException(HttpStatus.FORBIDDEN, "Forbidden", new HttpHeaders(),
                new byte[0], StandardCharsets.UTF_8);
        when(documentsApi.listDocuments()).thenThrow(failure);

        final var error = assertThrows(DocumentAccessException.class, () -> calls.list(documentsApi));

        assertSame(failure, error.getCause());
        assertTrue(error.getMessage().contains("403"));
    }

    /**
     * Verifies that a connection failure is reported as the resource server being unavailable.
     */
    @Test
    void list_whenResourceServerCannotBeReached_throwsDocumentAccessException() {
        when(documentsApi.listDocuments()).thenThrow(new ResourceAccessException("connection refused"));

        final var error = assertThrows(DocumentAccessException.class, () -> calls.list(documentsApi));

        assertInstanceOf(ResourceAccessException.class, error.getCause());
    }

    /**
     * Verifies that a document that breaks the domain invariants is reported as an access failure.
     */
    @Test
    void list_whenResourceServerAnswersAnInvalidDocument_throwsDocumentAccessException() {
        when(documentsApi.listDocuments()).thenReturn(List.of(new DocumentResponse().id("1")));

        final var error = assertThrows(DocumentAccessException.class, () -> calls.list(documentsApi));

        assertInstanceOf(IllegalArgumentException.class, error.getCause());
    }
}
