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

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

// tag::social-success-handler[]
/**
 * Success handler of the sign-in with an external provider. The framework's authentication carries no factor
 * authority, so this handler grants the federated factor through {@link FactorGrantor} (the strong one when the
 * provider is trusted, see {@link FederatedFactorSelector}), makes the result the current authentication, saves the
 * security context again (the filter saved the first one before calling the handler), and then lets the usual handler
 * resume the saved request, for example the {@code /oauth2/authorize} that sent the user to the login page.
 */
@RequiredArgsConstructor
public class FederatedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    /** Adds the factor authority. */
    private final FactorGrantor factorGrantor;

    /** Chooses the factor. */
    private final FederatedFactorSelector factorSelector;

    /** Saves the security context, the same repository the sign-in filter uses. */
    private final SecurityContextRepository securityContextRepository;

    /** The handler that resumes the saved request. */
    private final AuthenticationSuccessHandler delegate;

    /** Holder of the security context of the thread. */
    private final SecurityContextHolderStrategy holderStrategy = SecurityContextHolder.getContextHolderStrategy();

    /**
     * Grants the factor and continues.
     *
     * @param request        the request.
     * @param response       the response.
     * @param authentication the authentication of the sign-in.
     * @throws IOException if the redirect fails.
     * @throws jakarta.servlet.ServletException if the redirect fails.
     */
    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws IOException, jakarta.servlet.ServletException {
        if (authentication instanceof final OAuth2AuthenticationToken token) {
            final var granted = factorGrantor.grant(token, factorSelector.authorityOf(token));
            final var context = holderStrategy.createEmptyContext();
            context.setAuthentication(granted);
            holderStrategy.setContext(context);
            securityContextRepository.saveContext(context, request, response);
            delegate.onAuthenticationSuccess(request, response, granted);
            return;
        }
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
// end::social-success-handler[]
