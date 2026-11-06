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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link MfaProperties}.
 */
class MfaPropertiesTest {

    /** Default number of attempts, as the application use cases default it. */
    private static final int DEFAULT_ATTEMPTS = 5;

    /** Default lockout, in minutes, as the application use cases default it. */
    private static final int DEFAULT_LOCKOUT_MINUTES = 15;

    /** Default validity, in days, as the application use cases default it. */
    private static final int DEFAULT_VALIDITY_DAYS = 30;

    /** Configured number of attempts. */
    private static final int ATTEMPTS = 3;

    /** Configured lockout, in minutes. */
    private static final int LOCKOUT_MINUTES = 5;

    /** Configured validity, in days. */
    private static final int VALIDITY_DAYS = 7;

    /**
     * Verifies that nothing configured yields the defaults the application use cases use.
     */
    @Test
    void constructor_whenNothingIsConfigured_appliesDefaults() {
        final var properties = new MfaProperties(0, null, null, " ");

        assertEquals(DEFAULT_ATTEMPTS, properties.maxFailedAttempts());
        assertEquals(Duration.ofMinutes(DEFAULT_LOCKOUT_MINUTES), properties.lockout());
        assertEquals(Duration.ofDays(DEFAULT_VALIDITY_DAYS), properties.trustedDeviceValidity());
        assertEquals("Irurueta Auth Server", properties.totpIssuer());
    }

    /**
     * Verifies that configured values are kept.
     */
    @Test
    void constructor_whenValuesAreConfigured_keepsThem() {
        final var properties = new MfaProperties(ATTEMPTS, Duration.ofMinutes(LOCKOUT_MINUTES),
                Duration.ofDays(VALIDITY_DAYS), "Acme");

        assertEquals(ATTEMPTS, properties.maxFailedAttempts());
        assertEquals(Duration.ofMinutes(LOCKOUT_MINUTES), properties.lockout());
        assertEquals(Duration.ofDays(VALIDITY_DAYS), properties.trustedDeviceValidity());
        assertEquals("Acme", properties.totpIssuer());
    }
}
