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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.passkeys.PasskeyNotFoundException;
import jakarta.validation.ConstraintViolationException;
import java.net.URI;
import java.util.Set;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * Unit tests of {@link PasskeyExceptionHandler}.
 */
class PasskeyExceptionHandlerTest {

    /** Maximum age of a step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Builds the step-up challenge. */
    private final MfaExceptionHandler mfaExceptionHandler = new MfaExceptionHandler();

    /** Handler under test. */
    private final PasskeyExceptionHandler handler = new PasskeyExceptionHandler(mfaExceptionHandler);

    /**
     * Checks the answer to a passkey the account does not have.
     */
    @Test
    void handleNotFound_whenCalled_answersNotFoundAsAProblem() {
        final var response = handler.handleNotFound(new PasskeyNotFoundException("none"));

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        final var problem = response.getBody();
        assertNotNull(problem);
        assertEquals(URI.create("urn:problem:passkeys:passkey-not-found"), problem.getType());
        assertEquals("none", problem.getDetail());
    }

    /**
     * Checks the answer to a label the use case refuses.
     */
    @Test
    void handleInvalidLabel_whenCalled_answersBadRequestAsAProblem() {
        final var response = handler.handleInvalidLabel(new IllegalArgumentException("too long"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        final var problem = response.getBody();
        assertNotNull(problem);
        assertEquals(URI.create("urn:problem:passkeys:invalid-label"), problem.getType());
        assertEquals("too long", problem.getDetail());
    }

    /**
     * Checks the answer to a path parameter that breaks the constraints of the contract.
     */
    @Test
    void handleInvalidParameter_whenCalled_answersBadRequestAsAProblem() {
        final var response = handler.handleInvalidParameter(new ConstraintViolationException("bad id", Set.of()));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        final var problem = response.getBody();
        assertNotNull(problem);
        assertEquals(URI.create("urn:problem:passkeys:invalid-parameter"), problem.getType());
        assertEquals("bad id", problem.getDetail());
    }

    /**
     * Checks that the step-up challenge is the one of the rest of the account API.
     */
    @Test
    void handleInsufficientUserAuthentication_whenCalled_answersTheSameChallengeAsTheMfaHandler() {
        final var exception = new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR,
                Duration.ofMinutes(STEP_UP_MINUTES));

        final var response = handler.handleInsufficientUserAuthentication(exception);
        final var expected = mfaExceptionHandler.handleInsufficientUserAuthentication(exception);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(expected.getHeaders(), response.getHeaders());
        assertSame(exception.getAcrValues(), exception.getAcrValues());
    }
}
