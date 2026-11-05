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

package com.irurueta.authserver.authorization.api.web;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Base of the exception handlers of the REST API: every problem detail is answered as
 * {@code application/problem+json} (RFC 9457), as the contracts under {@code apis/} declare.
 * <p>
 * The interfaces generated from a contract map each operation with the media types it produces, for example
 * {@code application/json} and {@code application/problem+json}. Spring MVC keeps those as the producible types of
 * an error answer too and, for a client that accepts anything, would pick the first one: a problem detail would then
 * go out as {@code application/json}. Setting the content type of every problem answer keeps the contract's media
 * type whatever the order of the generated list.
 * <p>
 * It is not an advice itself: each feature declares its own {@code @RestControllerAdvice} extending it, scoped to its
 * controller.
 */
public class ProblemJsonExceptionHandler extends ResponseEntityExceptionHandler {

    /**
     * Answers a problem detail with its own status, as {@code application/problem+json}.
     *
     * @param problem the problem.
     * @return the response carrying the problem.
     */
    protected static ResponseEntity<ProblemDetail> problemResponse(final ProblemDetail problem) {
        return problemResponse(problem, new HttpHeaders());
    }

    /**
     * Answers a problem detail with its own status and the given headers, as {@code application/problem+json}.
     *
     * @param problem the problem.
     * @param headers headers of the answer, such as {@code Retry-After}.
     * @return the response carrying the problem.
     */
    protected static ResponseEntity<ProblemDetail> problemResponse(final ProblemDetail problem,
                                                                   final HttpHeaders headers) {
        return ResponseEntity.status(problem.getStatus())
                .headers(headers)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(problem);
    }

    /**
     * Sets the problem media type on the answers built by the parent class, such as request validation failures.
     *
     * @param body       body of the answer, normally a problem detail.
     * @param headers    headers of the answer.
     * @param statusCode status of the answer.
     * @param request    the current request.
     * @return the answer.
     */
    @Override
    protected ResponseEntity<Object> createResponseEntity(@Nullable final Object body, final HttpHeaders headers,
                                                          final HttpStatusCode statusCode, final WebRequest request) {
        if (!(body instanceof ProblemDetail)) {
            return super.createResponseEntity(body, headers, statusCode, request);
        }
        final var problemHeaders = new HttpHeaders();
        problemHeaders.putAll(headers);
        problemHeaders.setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        return super.createResponseEntity(body, problemHeaders, statusCode, request);
    }
}
