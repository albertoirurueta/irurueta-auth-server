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

package com.irurueta.authserver.bff.api.web.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

// tag::bff-login-success[]
/**
 * Sends the browser, once the OAuth2 login has succeeded, back to the {@code returnTo} that {@link BffLoginController}
 * validated and kept in the session. The attribute is read once and removed, and validated again by
 * {@link ReturnToValidator} before it is used, so a value that reached the session any other way can never become an
 * open redirect; when it is absent or not allowed, the browser goes to the root of the application.
 */
@Component
@RequiredArgsConstructor
public class ReturnToAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    /** Session attribute, owned by the BFF, holding the validated {@code returnTo} of the login in progress. */
    public static final String RETURN_TO_ATTRIBUTE = ReturnToAuthenticationSuccessHandler.class.getName()
            + ".RETURN_TO";

    /** Where the browser goes when there is no allowed {@code returnTo}: the root of the application. */
    static final String DEFAULT_TARGET = "/";

    /** Decides which {@code returnTo} values are safe. */
    private final ReturnToValidator returnToValidator;

    /**
     * Takes the {@code returnTo} out of the session and decides where the browser goes.
     *
     * @param request        the request of the login callback.
     * @param response       the response.
     * @param authentication the new authentication.
     * @return the validated {@code returnTo}, or {@link #DEFAULT_TARGET}.
     */
    @Override
    protected String determineTargetUrl(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) {
        final var session = request.getSession(false);
        if (session == null) {
            return DEFAULT_TARGET;
        }
        final var returnTo = session.getAttribute(RETURN_TO_ATTRIBUTE);
        session.removeAttribute(RETURN_TO_ATTRIBUTE);
        return returnTo instanceof String target && returnToValidator.isAllowed(target) ? target : DEFAULT_TARGET;
    }
}
// end::bff-login-success[]
