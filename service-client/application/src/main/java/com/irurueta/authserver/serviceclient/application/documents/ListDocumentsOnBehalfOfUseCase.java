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

package com.irurueta.authserver.serviceclient.application.documents;

import com.irurueta.authserver.serviceclient.domain.documents.Document;
import com.irurueta.authserver.serviceclient.domain.documents.OnBehalfOfDocumentGateway;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Use case that lists the documents a user may see, on behalf of that user (token exchange).
 */
@Service
@RequiredArgsConstructor
public class ListDocumentsOnBehalfOfUseCase {

    /** Port to the documents on the resource server on behalf of a user. */
    private final OnBehalfOfDocumentGateway onBehalfOfDocumentGateway;

    /**
     * Lists the documents the user may see.
     *
     * @param subjectToken access token of the user.
     * @return the documents, empty when there are none.
     * @throws IllegalArgumentException if the subject token is null or blank.
     */
    public List<Document> execute(final String subjectToken) {
        if (!StringUtils.hasText(subjectToken)) {
            throw new IllegalArgumentException("subjectToken is required");
        }
        return onBehalfOfDocumentGateway.listDocumentsAs(subjectToken);
    }
}
