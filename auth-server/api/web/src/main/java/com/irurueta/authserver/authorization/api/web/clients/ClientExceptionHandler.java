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

package com.irurueta.authserver.authorization.api.web.clients;

import com.irurueta.authserver.authorization.api.web.ProblemJsonExceptionHandler;
import com.irurueta.authserver.authorization.domain.clients.ClientAlreadyExistsException;
import com.irurueta.authserver.authorization.domain.clients.ClientNotFoundException;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates the failures of {@link ClientAdminController} to RFC 9457 problem details, answered as
 * {@code application/problem+json}. Request validation failures are handled by the parent class.
 */
@RestControllerAdvice(assignableTypes = ClientAdminController.class)
public class ClientExceptionHandler extends ProblemJsonExceptionHandler {

    /** Base of the problem type URNs. */
    private static final String TYPE_BASE = "urn:problem:client:";

    /**
     * Answers an unknown client.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(ClientNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(final ClientNotFoundException exception) {
        return respond(HttpStatus.NOT_FOUND, "not-found", "Client not found", exception.getMessage());
    }

    /**
     * Answers a duplicated client identifier.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(ClientAlreadyExistsException.class)
    public ResponseEntity<ProblemDetail> handleAlreadyExists(final ClientAlreadyExistsException exception) {
        return respond(HttpStatus.CONFLICT, "already-exists", "Client already exists", exception.getMessage());
    }

    /**
     * Answers an invalid client definition or a secret operation that does not apply.
     *
     * @param exception the failure.
     * @return the problem detail.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleInvalid(final IllegalArgumentException exception) {
        return respond(HttpStatus.BAD_REQUEST, "invalid", "Invalid client", exception.getMessage());
    }

    /**
     * Builds a problem response.
     *
     * @param status HTTP status.
     * @param type   last segment of the problem type.
     * @param title  short summary.
     * @param detail explanation.
     * @return the response.
     */
    private static ResponseEntity<ProblemDetail> respond(
            final HttpStatus status, final String type, final String title, final String detail) {
        final var problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(TYPE_BASE + type));
        problem.setTitle(title);
        return problemResponse(problem);
    }
}
