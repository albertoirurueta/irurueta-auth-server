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
import com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

/**
 * Lists the documents through a generated client and translates every failure into a {@link
 * DocumentAccessException}, so no HTTP, OAuth2 or JSON type escapes through the ports. Messages and logs never carry
 * a token.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DocumentCalls {

    /** Maps the generated model onto the domain. */
    private final DocumentMapper documentMapper;

    // tag::service-client-gateway[]
    /**
     * Lists the documents the token behind the client may see.
     *
     * @param documentsApi the generated client, which sends the access token.
     * @return the documents, empty when there are none.
     * @throws DocumentAccessException if the token cannot be obtained, the resource server refuses it, cannot be
     *                                 reached or answers something that is not a list of documents.
     */
    public List<Document> list(final DocumentsApi documentsApi) {
        try {
            final var documents = documentsApi.listDocuments();
            return documents == null ? List.of() : documents.stream().map(documentMapper::toDomain).toList();
        } catch (final OAuth2AuthorizationException e) {
            log.warn("No access token for the resource server: {}", e.getError().getErrorCode());
            throw new DocumentAccessException("The access token could not be obtained", e);
        } catch (final RestClientResponseException e) {
            log.warn("The resource server answered {}", e.getStatusCode().value());
            throw new DocumentAccessException("The resource server answered " + e.getStatusCode().value(), e);
        } catch (final RestClientException e) {
            log.warn("The resource server cannot be reached: {}", e.getClass().getSimpleName());
            throw new DocumentAccessException("The resource server is unavailable", e);
        } catch (final IllegalArgumentException e) {
            log.warn("The resource server answered an invalid document");
            throw new DocumentAccessException("The resource server answered an invalid document", e);
        }
    }
    // end::service-client-gateway[]
}
