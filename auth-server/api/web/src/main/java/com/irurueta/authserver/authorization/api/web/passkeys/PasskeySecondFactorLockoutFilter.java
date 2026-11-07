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
package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies the second-factor lockout to a passkey that completes a second-factor step. It runs right before the
 * WebAuthn authentication filter on {@code POST /login/webauthn}: when the session already holds a signed-in user
 * (the password was presented, see {@link MfaAuthorizationManager#isUser}), the passkey is being used as that user's
 * second factor, and while {@link CheckSecondFactorLockoutUseCase} reports the user's second factor locked (after too
 * many failed codes of another factor) the request is answered {@code 401} and the chain does not continue, so a
 * passkey cannot be used to step around a lockout. A passkey used as the primary, passwordless sign-in (no user in
 * the session) is not affected: there is no account to look up before the assertion is verified.
 *
 * <p>Failed passkey assertions are deliberately <em>not</em> counted as failed second-factor attempts: an assertion
 * is a signature by a private key that never leaves the authenticator, over a fresh server challenge, so it cannot be
 * guessed the way a six-digit code can, and counting the user's cancelled or failed ceremonies would only let them
 * lock themselves out of their other factors.
 *
 * <p>It is not a bean: {@link PasskeyChainCustomizer} builds it (a {@code Filter} bean would also be registered by
 * Spring Boot in the servlet container, outside the security chain).
 */
@Slf4j
@RequiredArgsConstructor
public class PasskeySecondFactorLockoutFilter extends OncePerRequestFilter {

    /** Matches the post that verifies an authentication ceremony. */
    private static final RequestMatcher AUTHENTICATION = PathPatternRequestMatcher.pathPattern(
            HttpMethod.POST, PasskeyChainCustomizer.AUTHENTICATION_PATH);

    /** Resolves the account of the signed-in user. */
    private final SecondFactorUserResolver secondFactorUserResolver;

    /** Tells whether the second factor of a user is locked. */
    private final CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /**
     * Answers {@code 401} to a passkey completing the second factor of a locked user, and lets anything else through.
     *
     * @param request     the request.
     * @param response    the response.
     * @param filterChain the rest of the chain.
     * @throws ServletException if the rest of the chain fails.
     * @throws IOException      if the rest of the chain fails.
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain filterChain) throws ServletException, IOException {
        if (AUTHENTICATION.matches(request) && isLocked()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Tells whether the session holds a signed-in user whose second factor is locked. An account that no longer
     * exists is refused as well.
     *
     * @return {@code true} when the passkey must be refused.
     */
    private boolean isLocked() {
        final var authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        if (!MfaAuthorizationManager.isUser(authentication)) {
            return false;
        }
        try {
            final var locked = checkSecondFactorLockoutUseCase.execute(
                    secondFactorUserResolver.userIdOf(authentication.getName()));
            if (locked) {
                log.info("Passkey refused as a second factor: the second factor of the user is locked");
            }
            return locked;
        } catch (final UsernameNotFoundException e) {
            log.info("Passkey refused as a second factor: the account of the session no longer exists");
            return true;
        }
    }
}
