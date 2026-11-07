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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.mfa.FactorTimeline;
import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.MfaProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * The step-up rule of {@code StepUpGuard} for a browser session instead of a bearer token: while the account has a
 * confirmed second factor, a sensitive change (removing the phone) needs a session that shows a multi-factor sign-in
 * made within {@code authserver.mfa.step-up-max-age}; an account without a second factor cannot step up, so it is not
 * asked to.
 */
@Component
@RequiredArgsConstructor
public class PhoneSessionStepUp {

    /** Tells whether the account has a confirmed second factor. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Reads the factors of the session and when they were presented. */
    private final FactorTimeline factorTimeline;

    /** Multi-factor settings, with the maximum age of the sign-in. */
    private final MfaProperties mfaProperties;

    /** Clock the age of the sign-in is measured with. */
    private final Clock clock;

    /**
     * Tells whether the session may make a sensitive change to the account.
     *
     * @param userId         identifier of the account.
     * @param authentication the authentication of the session.
     * @return {@code true} when the account has no confirmed second factor, or the session is multi-factor and its
     *         sign-in is recent enough.
     */
    public boolean isSatisfied(final UUID userId, final Authentication authentication) {
        if (!hasConfirmedSecondFactorUseCase.execute(userId)) {
            return true;
        }
        if (!factorTimeline.isMultiFactor(authentication)) {
            return false;
        }
        return factorTimeline.authTime(authentication).filter(this::isRecent).isPresent();
    }

    /**
     * Tells whether a sign-in is recent enough.
     *
     * @param authTime instant of the sign-in.
     * @return {@code true} when it is not in the future and at most the maximum age old.
     */
    private boolean isRecent(final Instant authTime) {
        final var age = Duration.between(authTime, clock.instant());
        return !age.isNegative() && age.compareTo(mfaProperties.stepUpMaxAge()) <= 0;
    }
}
