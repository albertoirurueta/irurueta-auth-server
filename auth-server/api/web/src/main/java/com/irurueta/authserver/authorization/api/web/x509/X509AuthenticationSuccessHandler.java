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

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

// tag::x509-success-handler[]
/**
 * Completes a sign-in with a client certificate. The framework's authentication is a
 * {@code PreAuthenticatedAuthenticationToken}, which the stored authorizations cannot serialize and whose factor
 * authority is a plain one; this handler replaces it by the ordinary authentication of the account, with the
 * authorities the account and the session already had and the certificate factor stamped with the clock (which is what
 * {@code auth_time} and {@code max_age} are measured with), changes the session id and renews the CSRF token as the
 * other sign-in methods do, saves the security context and resumes the interrupted request.
 */
@RequiredArgsConstructor
public class X509AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    /** Adds the factor authority. */
    private final FactorGrantor factorGrantor;

    /** Saves the security context, in the request and in the session. */
    private final SecurityContextRepository securityContextRepository;

    /** Resumes the interrupted request. */
    private final AuthenticationSuccessHandler delegate;

    /** Holder of the security context of the thread. */
    private final SecurityContextHolderStrategy holderStrategy = SecurityContextHolder.getContextHolderStrategy();

    /** Strategy that changes the session id and renews the CSRF token, set once the chain is built. */
    @Setter
    private SessionAuthenticationStrategy sessionAuthenticationStrategy = new NullAuthenticatedSessionStrategy();

    /**
     * Replaces the authentication, grants the factor and continues.
     *
     * @param request        the request.
     * @param response       the response.
     * @param authentication the authentication the framework produced.
     * @throws IOException      if the redirect fails.
     * @throws ServletException if the redirect fails.
     */
    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication authentication) throws IOException, ServletException {
        final var authorities = authentication.getAuthorities().stream()
                .filter(authority -> authority instanceof FactorGrantedAuthority
                        || !FactorGrantedAuthority.X509_AUTHORITY.equals(authority.getAuthority()))
                .<GrantedAuthority>map(authority -> authority)
                .toList();
        final var signedIn = factorGrantor.grant(
                UsernamePasswordAuthenticationToken.authenticated(authentication.getPrincipal(), null, authorities),
                FactorGrantedAuthority.X509_AUTHORITY);
        sessionAuthenticationStrategy.onAuthentication(signedIn, request, response);
        final var context = holderStrategy.createEmptyContext();
        context.setAuthentication(signedIn);
        holderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        delegate.onAuthenticationSuccess(request, response, signedIn);
    }
}
// end::x509-success-handler[]
