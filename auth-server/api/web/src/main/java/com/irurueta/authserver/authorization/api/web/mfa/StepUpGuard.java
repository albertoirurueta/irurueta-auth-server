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

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.MfaProperties;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationContextClass;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

// tag::mfa-step-up-guard[]
/**
 * Guards the API operations that remove or reset a second factor (disabling the authenticator app, generating new
 * recovery codes, revoking a trusted device): a stolen token, or a session left open, must not be enough to weaken the
 * account. While the account has a confirmed second factor, the bearer token must show a multi-factor sign-in
 * ({@code acr} {@value AuthenticationContextClass#MULTI_FACTOR}) whose {@code auth_time} is within
 * {@code authserver.mfa.step-up-max-age}; otherwise an {@link InsufficientUserAuthenticationException} asks the client
 * to step up (RFC 9470). An account without a second factor cannot step up, so it is not asked to. The controllers call
 * it first; the {@code /api/**} chain itself is not changed.
 */
@Component
@RequiredArgsConstructor
public class StepUpGuard {

    /** Tells whether the account has a confirmed second factor. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Multi-factor settings, with the maximum age of the sign-in. */
    private final MfaProperties mfaProperties;

    /** Clock the age of the sign-in is measured with. */
    private final Clock clock;

    /**
     * Requires a recent multi-factor sign-in from the bearer token of the current request.
     *
     * @param userId identifier of the account the operation acts on.
     * @throws InsufficientUserAuthenticationException if the account has a confirmed second factor and the token does
     *                                                 not show a recent enough multi-factor sign-in.
     */
    public void requireRecentMultiFactor(final UUID userId) {
        if (!hasConfirmedSecondFactorUseCase.execute(userId)) {
            return;
        }
        final var maxAge = mfaProperties.stepUpMaxAge();
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof JwtAuthenticationToken token)
                || !isRecentMultiFactor(token.getToken(), maxAge)) {
            throw new InsufficientUserAuthenticationException(AuthenticationContextClass.MULTI_FACTOR, maxAge);
        }
    }

    /**
     * Tells whether a token shows a multi-factor sign-in that is recent enough.
     *
     * @param jwt    the bearer token.
     * @param maxAge maximum age of the sign-in.
     * @return {@code true} when {@code acr} is the multi-factor class and {@code auth_time} is at most {@code maxAge}
     *         old (and not in the future).
     */
    private boolean isRecentMultiFactor(final Jwt jwt, final Duration maxAge) {
        if (!AuthenticationContextClass.MULTI_FACTOR.equals(jwt.getClaimAsString(IdTokenClaimNames.ACR))) {
            return false;
        }
        final var authTime = jwt.getClaimAsInstant(IdTokenClaimNames.AUTH_TIME);
        if (authTime == null) {
            return false;
        }
        final var age = Duration.between(authTime, clock.instant());
        return !age.isNegative() && age.compareTo(maxAge) <= 0;
    }
}
// end::mfa-step-up-guard[]
