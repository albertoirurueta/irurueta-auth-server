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

import com.irurueta.authserver.bff.api.web.v1.generated.api.LogoutApi;
import com.irurueta.authserver.bff.api.web.v1.generated.model.LogoutResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Ends the session, as the contract {@code apis/bff/rest-server/bff-api-v1.yaml} describes it through the generated
 * {@link LogoutApi}. The request is CSRF protected by the security chain.
 */
@RestController
@RequiredArgsConstructor
public class BffLogoutController implements LogoutApi {

    /** Builds the logout URL of the authorization server. */
    private final OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler;

    /** The current request, injected as a thread-bound proxy. */
    private final HttpServletRequest request;

    /** The current response, injected as a thread-bound proxy. */
    private final HttpServletResponse response;

    // tag::bff-logout[]
    /**
     * Composes the RP-initiated logout URL while the ID token of the session is still at hand, then invalidates the
     * session and clears the security context. The SPA navigates to the returned URL.
     *
     * @return the URL that ends the single sign-on session of the authorization server.
     * @throws AuthenticationCredentialsNotFoundException if nobody is signed in, answered 401 by the chain.
     */
    @Override
    public ResponseEntity<LogoutResponse> logout() {
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new AuthenticationCredentialsNotFoundException("Nobody is signed in");
        }
        try {
            logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        } catch (final IOException | ServletException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "The logout URL could not be built", e);
        }
        final var url = (String) request.getAttribute(UrlCapturingRedirectStrategy.URL_ATTRIBUTE);
        new SecurityContextLogoutHandler().logout(request, response, authentication);
        return ResponseEntity.ok(new LogoutResponse(url));
    }
    // end::bff-logout[]
}
