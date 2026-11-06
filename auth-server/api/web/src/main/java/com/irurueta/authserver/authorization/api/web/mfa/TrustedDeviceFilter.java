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

import static com.irurueta.authserver.authorization.api.web.mfa.SecondFactorRequiredEntryPoint.SECOND_FACTOR_PATH;

import com.irurueta.authserver.authorization.application.mfa.FindTrustedDeviceUseCase;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

/**
 * Lets a browser that was trusted earlier skip the second factor. When a signed-in user presents the
 * {@code __Host-TRUSTED-DEVICE} cookie and the token belongs to a device of that same user that has neither expired
 * nor been revoked, the authentication of the session is replaced by one that also holds the second-factor
 * authority, and the session is saved. A browser sent to the second-factor page when it is already trusted resumes
 * the request that was interrupted instead of being asked for a code.
 */
@RequiredArgsConstructor
public class TrustedDeviceFilter extends OncePerRequestFilter {

    /** Matches the request of the second-factor page. */
    private final PathPatternRequestMatcher secondFactorPageMatcher =
            PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, SECOND_FACTOR_PATH);

    /** Use case that finds the trusted device of a token. */
    private final FindTrustedDeviceUseCase findTrustedDeviceUseCase;

    /** Resolves the identifier of the account of the signed-in user. */
    private final SecondFactorUserResolver userResolver;

    /** Adds the factor authority to an authentication. */
    private final FactorGrantor factorGrantor;

    /** Repository the upgraded security context is saved to. */
    private final SecurityContextRepository securityContextRepository;

    /** Handler that resumes the request that was interrupted. */
    private final AuthenticationSuccessHandler resumeHandler;

    /** Authority of the second factor the device skips. */
    private final String authority;

    /**
     * Upgrades the authentication when the request carries the cookie of a valid trusted device.
     *
     * @param request  the request.
     * @param response the response.
     * @param chain    the rest of the chain.
     * @throws ServletException if the chain fails.
     * @throws IOException      if the response cannot be written.
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain chain) throws ServletException, IOException {
        final var cookie = WebUtils.getCookie(request, TrustedDeviceCookieWriter.COOKIE_NAME);
        final var current = SecurityContextHolder.getContext().getAuthentication();
        if (cookie != null && needsSecondFactor(current) && isTrusted(current, cookie.getValue())) {
            final var upgraded = factorGrantor.grant(current, authority);
            final var context = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
            context.setAuthentication(upgraded);
            SecurityContextHolder.getContextHolderStrategy().setContext(context);
            securityContextRepository.saveContext(context, request, response);
            if (secondFactorPageMatcher.matches(request)) {
                resumeHandler.onAuthenticationSuccess(request, response, upgraded);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    /**
     * Tells whether an authentication is a signed-in user that does not hold the second factor yet.
     *
     * @param authentication the authentication of the request, possibly {@code null}.
     * @return {@code true} when a user is signed in and the second-factor authority is missing.
     */
    private boolean needsSecondFactor(final Authentication authentication) {
        return authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)
                && authentication.getAuthorities().stream()
                .noneMatch(granted -> authority.equals(granted.getAuthority()));
    }

    /**
     * Tells whether a token identifies a valid trusted device of the signed-in user.
     *
     * @param authentication the signed-in user.
     * @param token          the raw token of the cookie.
     * @return {@code true} when the device exists and belongs to the user; the use case only finds devices that have
     *         been neither revoked nor expired.
     */
    private boolean isTrusted(final Authentication authentication, final String token) {
        try {
            final var userId = userResolver.userIdOf(authentication.getName());
            return findTrustedDeviceUseCase.execute(userId, token)
                    .filter(device -> userId.equals(device.userId()))
                    .isPresent();
        } catch (final UsernameNotFoundException e) {
            logger.debug("The user of the trusted device cookie does not exist", e);
            return false;
        }
    }
}
