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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.irurueta.authserver.authorization.api.web.mfa.ReauthenticationRequiredException;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredException;
import java.io.IOException;
import java.time.Duration;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Unit tests of {@link DeviceVerificationErrorHandler}.
 */
@ExtendWith(MockitoExtension.class)
class DeviceVerificationErrorHandlerTest {

    /** Path of the verification page. */
    private static final String PATH = "/oauth2/device_verification";

    /** Status of a response that asks for fewer requests. */
    private static final int TOO_MANY_REQUESTS = 429;

    /** Whole seconds of a wait that is not a whole number of seconds. */
    private static final long HALF_SECOND_WAIT_SECONDS = 90;

    /** The fraction of a second of that wait, in milliseconds. */
    private static final long HALF_SECOND = 500;

    /** Handler of the failures that go to the second-factor page. */
    @Mock
    private AuthenticationFailureHandler secondFactorHandler;

    /**
     * Verifies that too many attempts are answered with {@code 429} and the wait rounded up to whole seconds.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenTooManyAttempts_answers429WithRetryAfter() throws Exception {
        final var response = new MockHttpServletResponse();

        handler().onAuthenticationFailure(new MockHttpServletRequest(), response,
                new DeviceVerificationRateLimitedException(
                        Duration.ofSeconds(HALF_SECOND_WAIT_SECONDS).plusMillis(HALF_SECOND)));

        assertEquals(TOO_MANY_REQUESTS, response.getStatus());
        assertEquals("91", response.getHeader("Retry-After"));
        verifyNoInteractions(secondFactorHandler);
    }

    /**
     * Verifies that a wait of less than a second is announced as one second.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenTheWaitIsZero_announcesOneSecond() throws Exception {
        final var response = new MockHttpServletResponse();

        handler().onAuthenticationFailure(new MockHttpServletRequest(), response,
                new DeviceVerificationRateLimitedException(Duration.ZERO));

        assertEquals("1", response.getHeader("Retry-After"));
    }

    /**
     * Verifies that a user who owes a second factor is handed to the second-factor handler.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenASecondFactorIsOwed_delegates() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var failure = new SecondFactorRequiredException();

        handler().onAuthenticationFailure(request, response, failure);

        verify(secondFactorHandler).onAuthenticationFailure(request, response, failure);
    }

    /**
     * Verifies that a stale sign-in is handed to the second-factor handler too.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenReauthenticationIsRequired_delegates() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var failure = new ReauthenticationRequiredException();

        handler().onAuthenticationFailure(request, response, failure);

        verify(secondFactorHandler).onAuthenticationFailure(request, response, failure);
    }

    /**
     * Verifies that any other failure sends the browser back to the page with {@code ?error}, whatever the reason.
     *
     * @throws IOException      if the handler fails.
     * @throws ServletException if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenTheCodeIsRefused_redirectsToThePageWithError()
            throws IOException, ServletException {
        final var response = new MockHttpServletResponse();

        handler().onAuthenticationFailure(new MockHttpServletRequest(), response,
                new OAuth2AuthenticationException(new OAuth2Error("access_denied")));

        assertEquals(PATH + "?error", response.getRedirectedUrl());
        verify(secondFactorHandler, never()).onAuthenticationFailure(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    /**
     * Builds the handler.
     *
     * @return the handler.
     */
    private DeviceVerificationErrorHandler handler() {
        return new DeviceVerificationErrorHandler(secondFactorHandler, PATH);
    }
}
