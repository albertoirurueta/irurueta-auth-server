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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.bff.domain.documents.DocumentNotFoundException;
import com.irurueta.authserver.bff.domain.documents.DocumentsForbiddenException;
import com.irurueta.authserver.bff.domain.documents.DocumentsStepUpRequiredException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnauthorizedException;
import com.irurueta.authserver.bff.domain.documents.DocumentsUnavailableException;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

/**
 * Unit tests of {@link DocumentsExceptionHandler}.
 */
class DocumentsExceptionHandlerTest {

    /** Message of the failures; it must never reach the answer. */
    private static final String SECRET = "internal detail";

    /** Authentication context class of a step-up request. */
    private static final String ACR_VALUES = "urn:irurueta:acr:mfa";

    /** Seconds of the maximum age of a step-up request. */
    private static final long MAX_AGE_SECONDS = 300L;

    /** Handler under test. */
    private final DocumentsExceptionHandler handler = new DocumentsExceptionHandler();

    /**
     * A session without a valid token maps to 401.
     */
    @Test
    void handleUnauthorized_whenCalled_answersUnauthorized() {
        assertProblem(handler.handleUnauthorized(new DocumentsUnauthorizedException(SECRET, null)),
                HttpStatus.UNAUTHORIZED, "unauthorized");
    }

    /**
     * A step-up request maps to 401 with the values the resource server asked for.
     */
    @Test
    void handleStepUpRequired_whenValuesAreKnown_answersUnauthorizedWithThem() {
        final var response = handler.handleStepUpRequired(new DocumentsStepUpRequiredException(SECRET, ACR_VALUES,
                Duration.ofSeconds(MAX_AGE_SECONDS), null));

        assertProblem(response, HttpStatus.UNAUTHORIZED, "step-up-required");
        final var properties = response.getBody().getProperties();
        assertEquals(ACR_VALUES, properties.get(DocumentsExceptionHandler.ACR_VALUES_PROPERTY));
        assertEquals(MAX_AGE_SECONDS, properties.get(DocumentsExceptionHandler.MAX_AGE_PROPERTY));
    }

    /**
     * A step-up request that names no value maps to 401 without those properties.
     */
    @Test
    void handleStepUpRequired_whenValuesAreUnknown_answersUnauthorizedWithoutThem() {
        final var response = handler.handleStepUpRequired(new DocumentsStepUpRequiredException(SECRET, null, null,
                null));

        assertProblem(response, HttpStatus.UNAUTHORIZED, "step-up-required");
        assertNull(response.getBody().getProperties());
    }

    /**
     * A forbidden operation maps to 403.
     */
    @Test
    void handleForbidden_whenCalled_answersForbidden() {
        assertProblem(handler.handleForbidden(new DocumentsForbiddenException(SECRET, null)),
                HttpStatus.FORBIDDEN, "forbidden");
    }

    /**
     * A missing document maps to 404.
     */
    @Test
    void handleNotFound_whenCalled_answersNotFound() {
        assertProblem(handler.handleNotFound(new DocumentNotFoundException(SECRET, null)),
                HttpStatus.NOT_FOUND, "not-found");
    }

    /**
     * An unavailable resource server maps to 502.
     */
    @Test
    void handleUnavailable_whenCalled_answersBadGateway() {
        assertProblem(handler.handleUnavailable(new DocumentsUnavailableException(SECRET, null)),
                HttpStatus.BAD_GATEWAY, "unavailable");
    }

    /**
     * Checks a problem answer.
     *
     * @param response the answer.
     * @param status   the expected status.
     * @param type     the expected last segment of the problem type.
     */
    private static void assertProblem(final ResponseEntity<ProblemDetail> response, final HttpStatus status,
            final String type) {
        assertEquals(status, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        final var body = response.getBody();
        assertNotNull(body);
        assertEquals(DocumentsExceptionHandler.TYPE_BASE + type, body.getType().toString());
        assertEquals(status.value(), body.getStatus());
        assertFalse(body.getDetail().contains(SECRET));
    }
}
