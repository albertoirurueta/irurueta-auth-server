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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * Sends a user who has presented a primary factor but not yet the second one to the second-factor page, after saving
 * the request being served (typically {@code /oauth2/authorize?...}) so the sign-in resumes where it left off once the
 * second factor is verified.
 */
@RequiredArgsConstructor
public class SecondFactorRequiredEntryPoint implements AuthenticationEntryPoint {

    /** Path of the second-factor page. */
    public static final String SECOND_FACTOR_PATH = "/login/second-factor";

    /** Strategy that redirects, honouring the context path. */
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /** Cache that keeps the request to resume after the second factor, shared with the form login. */
    private final RequestCache requestCache;

    /**
     * Saves the request and redirects to the second-factor page.
     *
     * @param request       the request that needs a second factor.
     * @param response      the response to redirect.
     * @param authException why the request was refused.
     * @throws IOException if the redirect cannot be sent.
     */
    @Override
    public void commence(final HttpServletRequest request, final HttpServletResponse response,
                         final AuthenticationException authException) throws IOException {
        requestCache.saveRequest(request, response);
        redirectStrategy.sendRedirect(request, response, SECOND_FACTOR_PATH);
    }
}
