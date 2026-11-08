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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RestOnBehalfOfDocumentGateway}.
 */
@ExtendWith(MockitoExtension.class)
class RestOnBehalfOfDocumentGatewayTest {

    /** The user's token. */
    private static final String SUBJECT_TOKEN = "user-token";

    /** Builds the documents client of a user. */
    @Mock
    private OnBehalfOfDocumentsApis onBehalfOfDocumentsApis;

    /** Documents client of the user. */
    @Mock
    private DocumentsApi documentsApi;

    /** Translates the answers and failures. */
    @Mock
    private DocumentCalls documentCalls;

    /** Gateway under test. */
    @InjectMocks
    private RestOnBehalfOfDocumentGateway gateway;

    /**
     * Verifies that the documents are read through the client of the user.
     */
    @Test
    void listDocumentsAs_whenCalled_returnsWhatTheCallsReturn() {
        final var documents = List.of(new Document("1", "alice", "Title"));
        when(onBehalfOfDocumentsApis.forSubject(SUBJECT_TOKEN)).thenReturn(documentsApi);
        when(documentCalls.list(documentsApi)).thenReturn(documents);

        assertSame(documents, gateway.listDocumentsAs(SUBJECT_TOKEN));
    }
}
