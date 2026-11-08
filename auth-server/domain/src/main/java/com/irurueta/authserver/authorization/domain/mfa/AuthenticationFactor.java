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
package com.irurueta.authserver.authorization.domain.mfa;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

/**
 * A way of authenticating, as registered by a feature.
 *
 * @param id        stable identifier of the factor, for example {@code totp}.
 * @param amrValue  value of the {@code amr} claim (RFC 8176) reported when the factor was used, for example
 *                  {@code otp}.
 * @param authority authority granted to an authentication that used the factor, for example {@code FACTOR_TOTP}.
 * @param strength    how much the factor proves on its own.
 * @param multiFactor whether the factor alone proves a multi-factor authentication, so a session holding only it
 *                    reaches the multi-factor class ({@code acr}) and passes a step-up: for example a sign-in at a
 *                    provider trusted for, and reporting, its own multi-factor authentication. Only a
 *                    {@link FactorStrength#PRIMARY_STRONG} factor can be one; a strong factor that proves a single
 *                    thing (a passkey whose user verification is not required, a certificate) is not.
 */
public record AuthenticationFactor(String id, String amrValue, String authority, FactorStrength strength,
        boolean multiFactor) {

    /**
     * Validates the factor.
     *
     * @throws IllegalArgumentException if a text is blank, the strength is missing, or a factor that is not
     *                                  {@link FactorStrength#PRIMARY_STRONG} claims to be multi-factor alone.
     */
    public AuthenticationFactor {
        requireText(id, "id");
        requireText(amrValue, "amrValue");
        requireText(authority, "authority");
        if (strength == null) {
            throw new IllegalArgumentException("strength must not be null");
        }
        if (multiFactor && strength != FactorStrength.PRIMARY_STRONG) {
            throw new IllegalArgumentException("only a PRIMARY_STRONG factor can be multi-factor alone");
        }
    }

    /**
     * Creates a factor that does not prove a multi-factor authentication alone, the usual case.
     *
     * @param id        stable identifier of the factor.
     * @param amrValue  value of the {@code amr} claim reported when the factor was used.
     * @param authority authority granted to an authentication that used the factor.
     * @param strength  how much the factor proves on its own.
     * @throws IllegalArgumentException if a text is blank or the strength is missing.
     */
    public AuthenticationFactor(final String id, final String amrValue, final String authority,
            final FactorStrength strength) {
        this(id, amrValue, authority, strength, false);
    }
}
