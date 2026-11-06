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

package com.irurueta.authserver.authorization.application.mfa;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

// tag::mfa-properties[]
/**
 * Multi-factor settings, bound once from {@code authserver.mfa.*} and injected wherever one of them is needed (the use
 * cases of this module and the step-up guard of the API). A value left out takes its default; an invalid one stops the
 * application at startup.
 *
 * @param maxFailedAttempts     consecutive failed second-factor attempts that lock the second factor (default 5).
 * @param lockout               how long the second factor stays locked (default 15 minutes).
 * @param trustedDeviceValidity how long a device stays trusted (default 30 days).
 * @param totpIssuer            issuer shown by the authenticator app (default {@code Irurueta Auth Server}).
 * @param stepUpMaxAge          how recent the multi-factor sign-in of a bearer token must be to remove or reset a
 *                              second factor through the API (default 5 minutes).
 */
@ConfigurationProperties("authserver.mfa")
public record MfaProperties(
        @DefaultValue("5") int maxFailedAttempts,
        @DefaultValue("PT15M") Duration lockout,
        @DefaultValue("P30D") Duration trustedDeviceValidity,
        @DefaultValue("Irurueta Auth Server") String totpIssuer,
        @DefaultValue("PT5M") Duration stepUpMaxAge) {

    /**
     * Validates the settings.
     *
     * @throws IllegalArgumentException if {@code maxFailedAttempts} is less than one, a duration is missing or not
     *                                  positive, or the issuer is blank.
     */
    public MfaProperties {
        if (maxFailedAttempts < 1) {
            throw new IllegalArgumentException("authserver.mfa.max-failed-attempts must be at least 1");
        }
        requirePositive(lockout, "lockout");
        requirePositive(trustedDeviceValidity, "trusted-device-validity");
        requirePositive(stepUpMaxAge, "step-up-max-age");
        if (totpIssuer == null || totpIssuer.isBlank()) {
            throw new IllegalArgumentException("authserver.mfa.totp-issuer must not be blank");
        }
    }

    /**
     * Rejects a missing or non-positive duration.
     *
     * @param value the duration.
     * @param key   the key of the setting, below {@code authserver.mfa}.
     * @throws IllegalArgumentException if the duration is missing, zero or negative.
     */
    private static void requirePositive(final Duration value, final String key) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException("authserver.mfa." + key + " must be positive");
        }
    }
}
// end::mfa-properties[]
