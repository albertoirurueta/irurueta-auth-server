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

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * Multi-factor settings, bound from {@code authserver.mfa.*}. The use cases of the application module read the same
 * keys with the same defaults, so both stay consistent when a key is left out.
 *
 * @param maxFailedAttempts    consecutive failed second-factor attempts that lock the second factor; a value that is
 *                             not positive means {@link #DEFAULT_MAX_FAILED_ATTEMPTS}.
 * @param lockout              how long the second factor stays locked; {@code null} means {@link #DEFAULT_LOCKOUT}.
 * @param trustedDeviceValidity how long a device stays trusted; {@code null} means
 *                             {@link #DEFAULT_TRUSTED_DEVICE_VALIDITY}.
 * @param totpIssuer           issuer shown by the authenticator app; blank means {@link #DEFAULT_TOTP_ISSUER}.
 */
@ConfigurationProperties("authserver.mfa")
public record MfaProperties(
        int maxFailedAttempts, Duration lockout, Duration trustedDeviceValidity, String totpIssuer) {

    /** Consecutive failures that lock the second factor when none is configured. */
    public static final int DEFAULT_MAX_FAILED_ATTEMPTS = 5;

    /** Lockout duration when none is configured. */
    public static final Duration DEFAULT_LOCKOUT = Duration.ofMinutes(15);

    /** Validity of a trusted device when none is configured. */
    public static final Duration DEFAULT_TRUSTED_DEVICE_VALIDITY = Duration.ofDays(30);

    /** Issuer of the authenticator entries when none is configured. */
    public static final String DEFAULT_TOTP_ISSUER = "Irurueta Auth Server";

    /**
     * Applies the defaults.
     *
     * @param maxFailedAttempts    consecutive failures that lock the second factor, not positive for the default.
     * @param lockout              lockout duration, {@code null} for the default.
     * @param trustedDeviceValidity trusted device validity, {@code null} for the default.
     * @param totpIssuer           issuer of the authenticator entries, blank for the default.
     */
    public MfaProperties {
        maxFailedAttempts = maxFailedAttempts > 0 ? maxFailedAttempts : DEFAULT_MAX_FAILED_ATTEMPTS;
        lockout = lockout != null ? lockout : DEFAULT_LOCKOUT;
        trustedDeviceValidity = trustedDeviceValidity != null ? trustedDeviceValidity : DEFAULT_TRUSTED_DEVICE_VALIDITY;
        totpIssuer = StringUtils.hasText(totpIssuer) ? totpIssuer : DEFAULT_TOTP_ISSUER;
    }
}
