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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityNotFoundException;
import com.irurueta.authserver.authorization.domain.social.LastSignInMethodException;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * Unit tests of {@link IdentityExceptionHandler}.
 */
class IdentityExceptionHandlerTest {

    /** Maximum age of a step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Builds the step-up challenge. */
    private final MfaExceptionHandler mfaExceptionHandler = new MfaExceptionHandler();

    /** Handler under test. */
    private final IdentityExceptionHandler handler = new IdentityExceptionHandler(mfaExceptionHandler);

    /**
     * Checks the answer to an identity the account does not have.
     */
    @Test
    void handleNotFound_whenCalled_answersNotFoundAsAProblem() {
        final var response = handler.handleNotFound(new FederatedIdentityNotFoundException("none"));

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        final var problem = response.getBody();
        assertNotNull(problem);
        assertEquals(URI.create("urn:problem:identity:identity-not-found"), problem.getType());
        assertEquals("none", problem.getDetail());
    }

    /**
     * Checks the answer to an identity that is the last way to sign in.
     */
    @Test
    void handleLastSignInMethod_whenCalled_answersConflictAsAProblem() {
        final var response = handler.handleLastSignInMethod(new LastSignInMethodException("last"));

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        final var problem = response.getBody();
        assertNotNull(problem);
        assertEquals(URI.create("urn:problem:identity:last-sign-in-method"), problem.getType());
        assertEquals("last", problem.getDetail());
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
    }
}
