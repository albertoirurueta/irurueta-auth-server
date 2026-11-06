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

package com.irurueta.authserver.bff.api.web.logout;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.RedirectStrategy;

/**
 * Redirect strategy that does not redirect: it leaves the target URL in a request attribute. The logout success
 * handler of Spring Security builds the RP-initiated logout URL and redirects to it; a SPA calling the BFF with
 * {@code fetch} cannot follow such a redirect across origins, so the BFF returns the URL in a JSON body instead.
 */
public final class UrlCapturingRedirectStrategy implements RedirectStrategy {

    /** Request attribute holding the URL the handler wanted to redirect to. */
    public static final String URL_ATTRIBUTE = UrlCapturingRedirectStrategy.class.getName() + ".URL";

    @Override
    public void sendRedirect(final HttpServletRequest request, final HttpServletResponse response, final String url) {
        request.setAttribute(URL_ATTRIBUTE, url);
    }
}
