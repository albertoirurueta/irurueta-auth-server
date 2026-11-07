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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.api.web.mfa.InsufficientUserAuthenticationException;
import com.irurueta.authserver.authorization.api.web.mfa.MfaExceptionHandler;
import com.irurueta.authserver.authorization.application.sms.InvalidPhoneNumberException;
import com.irurueta.authserver.authorization.application.sms.SmsCountryNotAllowedException;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/** Unit tests of {@link OttExceptionHandler}. */
class OttExceptionHandlerTest {

    /** Maximum age of a step-up, in minutes. */
    private static final int STEP_UP_MINUTES = 5;

    /** Seconds to wait when rate limited. */
    private static final long WAIT_SECONDS = 30;

    /** Handler under test. */
    private final OttExceptionHandler handler = new OttExceptionHandler(new MfaExceptionHandler());

    /** A missing phone is answered not found as a problem. */
    @Test
    void handleNotFound_whenCalled_answersNotFoundAsAProblem() {
        final var response = handler.handleNotFound(new PhoneNotFoundException());

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, response.getHeaders().getContentType());
        assertEquals(URI.create("urn:problem:phone:phone-not-found"), response.getBody().getType());
    }

    /** An invalid number is answered bad request. */
    @Test
    void handleInvalidPhone_whenCalled_answersBadRequestAsAProblem() {
        final var response = handler.handleInvalidPhone(new InvalidPhoneNumberException());

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(URI.create("urn:problem:phone:invalid-phone"), response.getBody().getType());
    }

    /** A country that gets no SMS is answered bad request. */
    @Test
    void handleCountryNotAllowed_whenCalled_answersBadRequestAsAProblem() {
        final var response = handler.handleCountryNotAllowed(new SmsCountryNotAllowedException());

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(URI.create("urn:problem:phone:country-not-allowed"), response.getBody().getType());
    }

    /** A wrong code is answered bad request. */
    @Test
    void handleInvalidCode_whenCalled_answersBadRequestAsAProblem() {
        final var response = handler.handleInvalidCode(new InvalidPhoneCodeException());

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(URI.create("urn:problem:phone:invalid-code"), response.getBody().getType());
    }

    /** A rate-limited client is told to wait at least one second. */
    @Test
    void handleRateLimited_whenCalled_answersTooManyRequestsWithRetryAfter() {
        final var response = handler.handleRateLimited(
                new OttRateLimitExceededException(Duration.ofSeconds(WAIT_SECONDS)));
        final var shortWait = handler.handleRateLimited(new OttRateLimitExceededException(Duration.ofMillis(1)));

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertEquals("30", response.getHeaders().getFirst("Retry-After"));
        assertEquals("1", shortWait.getHeaders().getFirst("Retry-After"));
    }

    /** A missing step-up is answered as the multi-factor handler does. */
    @Test
    void handleInsufficientUserAuthentication_whenCalled_answersTheStepUpChallenge() {
        final var response = handler.handleInsufficientUserAuthentication(new InsufficientUserAuthenticationException(
                AuthenticationContextClass.MULTI_FACTOR, Duration.ofMinutes(STEP_UP_MINUTES)));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getHeaders().getFirst("WWW-Authenticate"));
    }
}
