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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import com.irurueta.authserver.authorization.domain.x509.CertificateAlreadyBoundException;
import com.irurueta.authserver.authorization.domain.x509.CertificateNotFoundException;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

/**
 * Unit tests of {@link CertificateExceptionHandler}.
 */
class CertificateExceptionHandlerTest {

    /** Maximum age of a step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Builds the step-up challenge. */
    private final MfaExceptionHandler mfaExceptionHandler = new MfaExceptionHandler();

    /** Handler under test. */
    private final CertificateExceptionHandler handler = new CertificateExceptionHandler(mfaExceptionHandler);

    /**
     * Checks the answer to a value that is not a usable certificate.
     */
    @Test
    void handleInvalidCertificate_whenCalled_answersBadRequestAsAProblem() {
        assertProblem(handler.handleInvalidCertificate(new InvalidCertificateException("bad")),
                HttpStatus.BAD_REQUEST, "invalid-certificate", "bad");
    }

    /**
     * Checks the answer to a certificate of another account.
     */
    @Test
    void handleAlreadyBound_whenCalled_answersConflictAsAProblem() {
        assertProblem(handler.handleAlreadyBound(new CertificateAlreadyBoundException("taken")),
                HttpStatus.CONFLICT, "certificate-already-bound", "taken");
    }

    /**
     * Checks the answer to a certificate the account does not have.
     */
    @Test
    void handleNotFound_whenCalled_answersNotFoundAsAProblem() {
        assertProblem(handler.handleNotFound(new CertificateNotFoundException("none")),
                HttpStatus.NOT_FOUND, "certificate-not-found", "none");
    }

    /**
     * Checks the answer to a certificate that is the last way to sign in.
     */
    @Test
    void handleLastSignInMethod_whenCalled_answersConflictAsAProblem() {
        assertProblem(handler.handleLastSignInMethod(new LastSignInMethodException("last")),
                HttpStatus.CONFLICT, "last-sign-in-method", "last");
    }

    /**
     * Checks that the step-up challenge is the one of the rest of the account API.
     */
    @Test
    void handleInsufficientUserAuthentication_whenCalled_answersTheSameChallengeAsTheMfaHandler() {
        final var exception = new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES));

        final var response = handler.handleInsufficientUserAuthentication(exception);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(mfaExceptionHandler.handleInsufficientUserAuthentication(exception).getHeaders(),
                response.getHeaders());
    }

    /**
     * Checks a problem response.
     *
     * @param response the response.
     * @param status   expected status.
     * @param type     expected last segment of the problem type.
     * @param detail   expected detail.
     */
    private static void assertProblem(final ResponseEntity<ProblemDetail> response, final HttpStatus status,
                                      final String type, final String detail) {
        assertEquals(status, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        final var problem = response.getBody();
        assertNotNull(problem);
        assertEquals(URI.create("urn:problem:certificate:" + type), problem.getType());
        assertEquals(detail, problem.getDetail());
    }
}
