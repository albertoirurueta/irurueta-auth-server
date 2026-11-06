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

package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.application.mfa.MfaConfiguration;
import com.irurueta.authserver.authorization.application.mfa.MfaProperties;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Checks how {@code authserver.mfa.*} is bound into {@link MfaProperties}: the defaults when nothing is configured,
 * the configured values otherwise, and a failed startup for an invalid value. It starts a minimal Spring context
 * (only the {@link MfaConfiguration} of the application module), hence an integration test.
 */
class MfaPropertiesIT {

    /** Default consecutive failures that lock the second factor. */
    private static final int DEFAULT_MAX_FAILED_ATTEMPTS = 5;

    /** Default lockout, in minutes. */
    private static final long DEFAULT_LOCKOUT_MINUTES = 15;

    /** Default validity of a trusted device, in days. */
    private static final long DEFAULT_VALIDITY_DAYS = 30;

    /** Default maximum age of a step-up, in minutes. */
    private static final long DEFAULT_STEP_UP_MINUTES = 5;

    /** Configured consecutive failures. */
    private static final int CONFIGURED_ATTEMPTS = 3;

    /** Runner of a context holding only the multi-factor configuration of the application module. */
    private final ApplicationContextRunner runner =
            new ApplicationContextRunner().withUserConfiguration(MfaConfiguration.class);

    /**
     * Verifies that nothing configured binds the defaults.
     */
    @Test
    void mfaProperties_whenNothingIsConfigured_bindsTheDefaults() {
        runner.run(context -> {
            final var properties = context.getBean(MfaProperties.class);
            assertEquals(DEFAULT_MAX_FAILED_ATTEMPTS, properties.maxFailedAttempts());
            assertEquals(Duration.ofMinutes(DEFAULT_LOCKOUT_MINUTES), properties.lockout());
            assertEquals(Duration.ofDays(DEFAULT_VALIDITY_DAYS), properties.trustedDeviceValidity());
            assertEquals("Irurueta Auth Server", properties.totpIssuer());
            assertEquals(Duration.ofMinutes(DEFAULT_STEP_UP_MINUTES), properties.stepUpMaxAge());
        });
    }

    /**
     * Verifies that configured values are bound.
     */
    @Test
    void mfaProperties_whenValuesAreConfigured_bindsThem() {
        runner.withPropertyValues("authserver.mfa.max-failed-attempts=" + CONFIGURED_ATTEMPTS,
                        "authserver.mfa.totp-issuer=Acme")
                .run(context -> {
                    final var properties = context.getBean(MfaProperties.class);
                    assertEquals(CONFIGURED_ATTEMPTS, properties.maxFailedAttempts());
                    assertEquals("Acme", properties.totpIssuer());
                });
    }

    /**
     * Verifies that an invalid value stops the context.
     */
    @Test
    void mfaProperties_whenMaxFailedAttemptsIsZero_failsAtStartup() {
        runner.withPropertyValues("authserver.mfa.max-failed-attempts=0")
                .run(context -> assertNotNull(context.getStartupFailure()));
    }
}
