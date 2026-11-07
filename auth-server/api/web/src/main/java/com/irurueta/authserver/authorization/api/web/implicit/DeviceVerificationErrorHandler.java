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

import com.irurueta.authserver.authorization.api.web.mfa.ReauthenticationRequiredException;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Error handler of the device verification endpoint. A user who owes a second factor goes where the authorization
 * endpoint sends them (the {@code secondFactorHandler}); too many attempts are answered {@code 429} with a
 * {@code Retry-After} header; any other failure (an unknown, expired or already used code, a denied consent) sends the
 * browser back to the verification page with {@code ?error}, which says nothing about the reason, so a code cannot be
 * told apart from a wrong one. Installing a handler replaces the framework's, which only answers {@code 400}.
 */
@RequiredArgsConstructor
public class DeviceVerificationErrorHandler implements AuthenticationFailureHandler {

    /** Name of the parameter that tells the verification page that the previous attempt failed. */
    static final String ERROR_PARAMETER = "error";

    /** Strategy that redirects, honouring the context path. */
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /** Handler of the failures that send the user to the second-factor page or to a new sign-in. */
    private final AuthenticationFailureHandler secondFactorHandler;

    /** Path of the verification page. */
    private final String verificationPath;

    /**
     * Handles a failed verification request.
     *
     * @param request   the request.
     * @param response  the response.
     * @param exception why the request failed.
     * @throws IOException      if the response cannot be written.
     * @throws ServletException if the second-factor handler fails.
     */
    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException exception) throws IOException, ServletException {
        if (exception instanceof DeviceVerificationRateLimitedException limited) {
            response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds(limited)));
            response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(), limited.getError().getDescription());
            return;
        }
        if (exception instanceof SecondFactorRequiredException
                || exception instanceof ReauthenticationRequiredException) {
            secondFactorHandler.onAuthenticationFailure(request, response, exception);
            return;
        }
        redirectStrategy.sendRedirect(request, response, verificationPath + "?" + ERROR_PARAMETER);
    }

    /**
     * Rounds the wait up to whole seconds, at least one.
     *
     * @param exception the failure.
     * @return the seconds to wait.
     */
    private static long retryAfterSeconds(final DeviceVerificationRateLimitedException exception) {
        final var wait = exception.retryAfter();
        final var seconds = wait.toSeconds() + (wait.toNanosPart() > 0 ? 1 : 0);
        return Math.max(1, seconds);
    }
}
