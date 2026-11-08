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

import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.IdentitiesPageApi;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Failure handler of the sign-in with an external provider. A refused link
 * ({@link FederatedAccountResolver#LINK_REFUSED}: the identity belongs to another account) goes back to the identities
 * page with the status {@code already-linked}; the session is still signed in as before, because a failed sign-in
 * never saves a security context. Any other failure is handled by the delegate, the generic failure of the login page.
 */
@RequiredArgsConstructor
public class FederatedAuthenticationFailureHandler implements AuthenticationFailureHandler {

    /** Query of the identities page after a refused link. */
    static final String ALREADY_LINKED_STATUS = "?status=already-linked";

    /** The handler of every other failure. */
    private final AuthenticationFailureHandler delegate;

    /**
     * Handles a failed sign-in or link.
     *
     * @param request   the request.
     * @param response  the response.
     * @param exception the failure.
     * @throws IOException      if the redirect fails.
     * @throws ServletException if the delegate fails.
     */
    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException exception) throws IOException, ServletException {
        if (exception instanceof final OAuth2AuthenticationException oauth2
                && FederatedAccountResolver.LINK_REFUSED.equals(oauth2.getError().getErrorCode())) {
            response.sendRedirect(request.getContextPath() + IdentitiesPageApi.PATH_IDENTITIES_PAGE
                    + ALREADY_LINKED_STATUS);
            return;
        }
        delegate.onAuthenticationFailure(request, response, exception);
    }
}
