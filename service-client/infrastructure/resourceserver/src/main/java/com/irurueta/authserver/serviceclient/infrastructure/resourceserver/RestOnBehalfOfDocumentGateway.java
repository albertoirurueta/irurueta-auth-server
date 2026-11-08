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

import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.domain.documents.OnBehalfOfDocumentGateway;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Documents of the resource server read on behalf of a user: the user's access token is exchanged (RFC 8693) for one
 * of the service client, which names the user as subject and the client as actor.
 */
@Component
@RequiredArgsConstructor
public class RestOnBehalfOfDocumentGateway implements OnBehalfOfDocumentGateway {

    /** Builds the documents client of one user. */
    private final OnBehalfOfDocumentsApis onBehalfOfDocumentsApis;

    /** Translates the answers and failures. */
    private final DocumentCalls documentCalls;

    @Override
    public List<Document> listDocumentsAs(final String subjectToken) {
        return documentCalls.list(onBehalfOfDocumentsApis.forSubject(subjectToken));
    }
}
