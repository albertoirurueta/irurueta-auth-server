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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * The X.509 filter of the sign-in path. Spring's filter always continues the chain, but the success handler of this
 * server resumes the interrupted request with a redirect and a failed sign-in is redirected to the login page, so the
 * rest of the chain must not run after a committed response. A request to the sign-in path that no handler answered
 * carried no usable certificate (none was presented, or the header came from a proxy nobody trusts): it goes back to
 * the login page too, instead of reaching a path nothing serves.
 */
public class X509LoginFilter extends X509AuthenticationFilter {

    /** Matcher of the sign-in requests, the same the parent filter authenticates. */
    private RequestMatcher signInRequests = request -> false;

    /**
     * Sets the requests that sign in with a certificate.
     *
     * @param requiresAuthenticationRequestMatcher matcher of the sign-in requests.
     */
    @Override
    public void setRequiresAuthenticationRequestMatcher(final RequestMatcher requiresAuthenticationRequestMatcher) {
        super.setRequiresAuthenticationRequestMatcher(requiresAuthenticationRequestMatcher);
        signInRequests = requiresAuthenticationRequestMatcher;
    }

    /**
     * Authenticates the request, when it is a sign-in with a certificate, and continues the chain unless the response
     * was answered.
     *
     * @param request  the request.
     * @param response the response.
     * @param chain    the rest of the chain.
     * @throws IOException      if a handler or the chain fails.
     * @throws ServletException if a handler or the chain fails.
     */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        super.doFilter(request, response, (ignoredRequest, ignoredResponse) -> { });
        if (response.isCommitted()) {
            return;
        }
        final var httpRequest = (HttpServletRequest) request;
        if (signInRequests.matches(httpRequest)) {
            ((HttpServletResponse) response).sendRedirect(httpRequest.getContextPath()
                    + X509ChainCustomizer.FAILURE_URL);
            return;
        }
        chain.doFilter(request, response);
    }
}
