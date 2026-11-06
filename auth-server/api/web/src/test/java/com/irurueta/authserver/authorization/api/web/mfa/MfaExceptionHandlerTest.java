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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.domain.totp.InvalidTotpCodeException;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException;
import java.net.URI;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;

/**
 * Unit tests of {@link MfaExceptionHandler}.
 */
class MfaExceptionHandlerTest {

    /** Handler under test. */
    private final MfaExceptionHandler handler = new MfaExceptionHandler();

    /**
     * Checks the answer to an authenticator app that is already enabled.
     */
    @Test
    void handleAlreadyEnabled_whenCalled_answersConflict() {
        final var response = handler.handleAlreadyEnabled(new TotpAlreadyEnabledException("enabled"));

        assertProblem(response.getStatusCode(), HttpStatus.CONFLICT, response.getBody(), "totp-already-enabled",
                "enabled");
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
    }

    /**
     * Checks the answer to a confirmation without an enrolment.
     */
    @Test
    void handleNotEnrolled_whenCalled_answersBadRequest() {
        final var response = handler.handleNotEnrolled(new TotpNotEnrolledException("none"));

        assertProblem(response.getStatusCode(), HttpStatus.BAD_REQUEST, response.getBody(), "totp-not-enrolled",
                "none");
    }

    /**
     * Checks the answer to a wrong code.
     */
    @Test
    void handleInvalidCode_whenCalled_answersBadRequest() {
        final var response = handler.handleInvalidCode(new InvalidTotpCodeException("wrong"));

        assertProblem(response.getStatusCode(), HttpStatus.BAD_REQUEST, response.getBody(), "invalid-code", "wrong");
    }

    /**
     * Checks the answer to a device the account does not have.
     */
    @Test
    void handleDeviceNotFound_whenCalled_answersNotFound() {
        final var id = UUID.randomUUID();

        final var response = handler.handleDeviceNotFound(new TrustedDeviceNotFoundException(id));

        assertProblem(response.getStatusCode(), HttpStatus.NOT_FOUND, response.getBody(), "trusted-device-not-found",
                "Trusted device not found: " + id);
    }

    /**
     * Checks a problem answer.
     *
     * @param actual   status of the response.
     * @param expected expected status.
     * @param body     the problem.
     * @param type     expected last segment of the type.
     * @param detail   expected detail.
     */
    private static void assertProblem(final HttpStatusCode actual,
                                      final HttpStatus expected, final ProblemDetail body,
                                      final String type, final String detail) {
        assertNotNull(body);
        assertEquals(expected, actual);
        assertEquals(expected.value(), body.getStatus());
        assertEquals(URI.create("urn:problem:mfa:" + type), body.getType());
        assertEquals(detail, body.getDetail());
    }
}
