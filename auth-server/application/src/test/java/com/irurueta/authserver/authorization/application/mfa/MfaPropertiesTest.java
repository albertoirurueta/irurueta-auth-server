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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link MfaProperties}. The defaults are applied by the binder from the {@code @DefaultValue}
 * annotations; the startup binding is covered by the integration tests.
 */
class MfaPropertiesTest {

    /** Configured number of attempts. */
    private static final int ATTEMPTS = 3;

    /** Configured lockout. */
    private static final Duration LOCKOUT = Duration.ofMinutes(5);

    /** Configured validity of a trusted device. */
    private static final Duration VALIDITY = Duration.ofDays(7);

    /** Configured step-up maximum age. */
    private static final Duration STEP_UP = Duration.ofMinutes(2);

    /** Configured issuer. */
    private static final String ISSUER = "Acme";

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var properties = new MfaProperties(ATTEMPTS, LOCKOUT, VALIDITY, ISSUER, STEP_UP);

        assertEquals(ATTEMPTS, properties.maxFailedAttempts());
        assertEquals(LOCKOUT, properties.lockout());
        assertEquals(VALIDITY, properties.trustedDeviceValidity());
        assertEquals(ISSUER, properties.totpIssuer());
        assertEquals(STEP_UP, properties.stepUpMaxAge());
    }

    /**
     * Verifies that fewer than one attempt is rejected.
     */
    @Test
    void constructor_whenMaxFailedAttemptsIsLessThanOne_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new MfaProperties(0, LOCKOUT, VALIDITY, ISSUER, STEP_UP));
    }

    /**
     * Verifies that a missing, zero or negative duration is rejected, whichever it is.
     */
    @Test
    void constructor_whenADurationIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new MfaProperties(ATTEMPTS, null, VALIDITY, ISSUER, STEP_UP));
        assertThrows(IllegalArgumentException.class,
                () -> new MfaProperties(ATTEMPTS, Duration.ZERO, VALIDITY, ISSUER, STEP_UP));
        assertThrows(IllegalArgumentException.class,
                () -> new MfaProperties(ATTEMPTS, LOCKOUT, VALIDITY.negated(), ISSUER, STEP_UP));
        assertThrows(IllegalArgumentException.class,
                () -> new MfaProperties(ATTEMPTS, LOCKOUT, VALIDITY, ISSUER, null));
    }

    /**
     * Verifies that a missing or blank issuer is rejected.
     */
    @Test
    void constructor_whenIssuerIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new MfaProperties(ATTEMPTS, LOCKOUT, VALIDITY, " ", STEP_UP));
        assertThrows(IllegalArgumentException.class,
                () -> new MfaProperties(ATTEMPTS, LOCKOUT, VALIDITY, null, STEP_UP));
    }
}
