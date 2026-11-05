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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Unit tests of {@link ProblemJsonExceptionHandler}.
 */
class ProblemJsonExceptionHandlerTest {

    /** Value of the extra header used by the tests. */
    private static final String RETRY_SECONDS = "7";

    /** Handler under test. */
    private final ProblemJsonExceptionHandler handler = new ProblemJsonExceptionHandler();

    /**
     * Verifies that a failure handled by the parent class, such as an unsupported request body, is answered as
     * {@code application/problem+json} with its own status.
     *
     * @throws Exception if the parent class fails to handle the exception.
     */
    @Test
    void handleException_whenParentBuildsProblem_answersProblemJson() throws Exception {
        final var exception = new HttpMediaTypeNotSupportedException(MediaType.TEXT_PLAIN,
                List.of(MediaType.APPLICATION_JSON));

        final var response = handler.handleException(exception, new ServletWebRequest(new MockHttpServletRequest()));

        assertNotNull(response);
        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        assertInstanceOf(ProblemDetail.class, response.getBody());
        assertEquals(List.of(MediaType.APPLICATION_JSON.toString()), response.getHeaders().get(HttpHeaders.ACCEPT));
    }

    /**
     * Verifies that an answer without a problem body keeps the headers it was given.
     */
    @Test
    void createResponseEntity_whenBodyIsNotAProblem_keepsHeaders() {
        final var headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);

        final var response = handler.createResponseEntity(null, headers, HttpStatus.BAD_REQUEST,
                new ServletWebRequest(new MockHttpServletRequest()));

        assertNull(response.getBody());
        assertEquals(MediaType.TEXT_PLAIN, response.getHeaders().getContentType());
    }

    /**
     * Verifies that a problem built by a feature is answered with its status, its headers and the problem media type.
     */
    @Test
    void problemResponse_whenHeadersAreGiven_answersProblemJsonWithThem() {
        final var problem = ProblemDetail.forStatus(HttpStatus.TOO_MANY_REQUESTS);
        final var headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, RETRY_SECONDS);

        final var response = ProblemJsonExceptionHandler.problemResponse(problem, headers);

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        assertEquals(RETRY_SECONDS, response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER));
        assertSame(problem, response.getBody());
    }

    /**
     * Verifies that a problem built by a feature without headers is answered as {@code application/problem+json}.
     */
    @Test
    void problemResponse_whenNoHeadersAreGiven_answersProblemJson() {
        final var problem = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);

        final var response = ProblemJsonExceptionHandler.problemResponse(problem);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        assertSame(problem, response.getBody());
    }
}
