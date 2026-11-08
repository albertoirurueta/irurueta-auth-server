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

package com.irurueta.authserver.bff.infrastructure.resourceserver;

import com.irurueta.authserver.bff.domain.documents.Document;
import com.irurueta.authserver.bff.domain.documents.DocumentGateway;
import com.irurueta.authserver.bff.domain.documents.DocumentNotFoundException;
import com.irurueta.authserver.bff.domain.documents.DocumentsForbiddenException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnauthorizedException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnavailableException;
import com.irurueta.authserver.bff.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import java.util.List;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

/**
 * Implements the documents port with the client generated from the resource server's contract. The call runs on behalf
 * of the signed-in user (the REST client adds the user's access token) and every failure becomes a domain exception:
 * a missing or unrenewable token and a {@code 401} are unauthorized, except a {@code 401} carrying a step-up challenge
 * (RFC 9470), which asks for a stronger or more recent authentication; a {@code 403} is forbidden, a {@code 404} not
 * found, and an unreachable resource server or any other answer unavailable. No token is ever logged.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RestDocumentGateway implements DocumentGateway {

    /** Documents client generated from the resource server's contract. */
    private final DocumentsApi documentsApi;

    /** Maps the generated model onto the domain. */
    private final DocumentMapper documentMapper;

    /** Reads the step-up challenge of a {@code 401} answer. */
    private final StepUpChallengeMapper stepUpChallengeMapper;

    // tag::bff-documents-gateway[]
    @Override
    public List<Document> list() {
        final var documents = call(documentsApi::listDocuments);
        return documents == null ? List.of() : documents.stream().map(documentMapper::toDomain).toList();
    }

    @Override
    public void deleteById(final String id) {
        call(() -> documentsApi.deleteDocumentWithHttpInfo(id));
    }

    /**
     * Calls the resource server and translates its failures into domain exceptions.
     *
     * @param operation the call.
     * @param <T>       type of the answer.
     * @return the answer of the resource server.
     */
    private <T> T call(final Supplier<T> operation) {
        try {
            return operation.get();
        } catch (final OAuth2AuthorizationException e) {
            log.warn("No access token for the resource server: {}", e.getError().getErrorCode());
            throw new DocumentsUnauthorizedException("The session has no valid token", e);
        } catch (final RestClientResponseException e) {
            throw translate(e);
        } catch (final RestClientException e) {
            log.warn("The resource server cannot be reached: {}", e.getClass().getSimpleName());
            throw new DocumentsUnavailableException("The resource server is unavailable", e);
        }
    }
    // end::bff-documents-gateway[]

    /**
     * Translates an error answer of the resource server.
     *
     * @param e the error answer.
     * @return the domain exception that describes it.
     */
    private RuntimeException translate(final RestClientResponseException e) {
        return switch (HttpStatus.resolve(e.getStatusCode().value())) {
            case UNAUTHORIZED -> {
                final var stepUp = stepUpChallengeMapper.toException(e.getResponseHeaders(), e);
                yield stepUp.isPresent() ? stepUp.get()
                        : new DocumentsUnauthorizedException("The resource server refused the token", e);
            }
            case FORBIDDEN -> new DocumentsForbiddenException("The token does not allow the operation", e);
            case NOT_FOUND -> new DocumentNotFoundException("The document does not exist", e);
            case null, default -> {
                log.warn("The resource server answered {}", e.getStatusCode().value());
                yield new DocumentsUnavailableException("The resource server failed", e);
            }
        };
    }
}
