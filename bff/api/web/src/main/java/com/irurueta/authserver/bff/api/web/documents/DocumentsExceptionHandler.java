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

package com.irurueta.authserver.bff.api.web.documents;

import com.irurueta.authserver.bff.domain.documents.DocumentNotFoundException;
import com.irurueta.authserver.bff.domain.documents.DocumentsForbiddenException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnauthorizedException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnavailableException;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates the failures of {@link DocumentsController} to RFC 9457 problem details, answered as
 * {@code application/problem+json}. The detail is a fixed text: the message of the failure, and anything the resource
 * server said, never reach the browser.
 */
@RestControllerAdvice(assignableTypes = DocumentsController.class)
public class DocumentsExceptionHandler {

    /** Base of the problem type URNs. */
    static final String TYPE_BASE = "urn:problem:documents:";

    /**
     * Answers a session without a valid token with 401, so the SPA signs the user in again.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(DocumentsUnauthorizedException.class)
    public ResponseEntity<ProblemDetail> handleUnauthorized(final DocumentsUnauthorizedException exception) {
        return respond(HttpStatus.UNAUTHORIZED, "unauthorized", "The session has no valid token");
    }

    /**
     * Answers an operation the user may not perform with 403.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(DocumentsForbiddenException.class)
    public ResponseEntity<ProblemDetail> handleForbidden(final DocumentsForbiddenException exception) {
        return respond(HttpStatus.FORBIDDEN, "forbidden", "The operation is not allowed");
    }

    /**
     * Answers a missing document, or someone else's, with 404.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(DocumentNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(final DocumentNotFoundException exception) {
        return respond(HttpStatus.NOT_FOUND, "not-found", "The document does not exist");
    }

    /**
     * Answers an unreachable or failing resource server with 502.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(DocumentsUnavailableException.class)
    public ResponseEntity<ProblemDetail> handleUnavailable(final DocumentsUnavailableException exception) {
        return respond(HttpStatus.BAD_GATEWAY, "unavailable", "The resource server is unavailable");
    }

    /**
     * Builds a problem response.
     *
     * @param status HTTP status.
     * @param type   last segment of the problem type.
     * @param detail explanation shown to the user.
     * @return the response.
     */
    private static ResponseEntity<ProblemDetail> respond(final HttpStatus status, final String type,
            final String detail) {
        final var problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(TYPE_BASE + type));
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(problem);
    }
}
