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
import com.irurueta.authserver.serviceclient.domain.documents.DocumentGateway;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Documents of the resource server read with the service client's own token (client credentials grant).
 */
@Component
@RequiredArgsConstructor
public class RestDocumentGateway implements DocumentGateway {

    /** Documents client whose requests carry the client credentials token. */
    private final DocumentsApi documentsApi;

    /** Translates the answers and failures. */
    private final DocumentCalls documentCalls;

    @Override
    public List<Document> listDocuments() {
        return documentCalls.list(documentsApi);
    }
}
