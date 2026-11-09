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

package com.irurueta.authserver.bff.api.web.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

// tag::bff-csrf-cookie-filter[]
/**
 * Makes the CSRF token reach the single page application. Spring Security loads the token lazily, so the
 * {@code XSRF-TOKEN} cookie would only be written when something reads the token; this filter reads it on every
 * request, so the SPA always finds the cookie (readable by its scripts) to copy into the {@code X-XSRF-TOKEN} header,
 * or into the {@code _csrf} parameter of its sign-out form.
 */
final class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain filterChain) throws ServletException, IOException {
        final var token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token != null) {
            // rendering the token value is what makes the repository write the cookie
            token.getToken();
        }
        filterChain.doFilter(request, response);
    }
}
// end::bff-csrf-cookie-filter[]
