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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * Forces a new sign-in: it discards the stale authentication of the session (the security context of the thread and
 * the one stored by the repository), saves the request being served (typically {@code /oauth2/authorize?...}) so it
 * resumes once the user has signed in again, and redirects to the login page.
 */
@RequiredArgsConstructor
public class ReauthenticationEntryPoint implements AuthenticationEntryPoint {

    /** Path of the login page. */
    public static final String LOGIN_PATH = "/login";

    /** Strategy that redirects, honouring the context path. */
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    /** Cache that keeps the request to resume after signing in, shared with the form login. */
    private final RequestCache requestCache;

    /** Repository that stores the security context of the session. */
    private final SecurityContextRepository securityContextRepository;

    /**
     * Clears the authentication, saves the request and redirects to the login page.
     *
     * @param request       the request that needs a new sign-in.
     * @param response      the response to redirect.
     * @param authException why the request was refused.
     * @throws IOException if the redirect cannot be sent.
     */
    @Override
    public void commence(final HttpServletRequest request, final HttpServletResponse response,
                         final AuthenticationException authException) throws IOException {
        SecurityContextHolder.clearContext();
        securityContextRepository.saveContext(new SecurityContextImpl(), request, response);
        requestCache.saveRequest(request, response);
        redirectStrategy.sendRedirect(request, response, LOGIN_PATH);
    }
}
