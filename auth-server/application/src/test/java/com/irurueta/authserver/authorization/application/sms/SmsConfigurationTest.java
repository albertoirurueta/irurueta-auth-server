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

package com.irurueta.authserver.authorization.application.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SmsConfiguration}.
 */
class SmsConfigurationTest {

    /** Spending window. */
    private static final Duration WINDOW = Duration.ofMinutes(30);

    /** Cost of Spain. */
    private static final long SPAIN_COST = 70_000L;

    /** Default cost. */
    private static final long DEFAULT_COST = 10_000L;

    /** Window cap. */
    private static final long WINDOW_CAP = 100_000L;

    /** Day cap. */
    private static final long DAY_CAP = 300_000L;

    /**
     * Verifies that the policy takes countries, costs, window and caps from the settings.
     */
    @Test
    void smsCostPolicy_whenSettingsAreGiven_buildsPolicyFromThem() {
        final var properties = new SmsProperties("ES", Set.of("ES"), Map.of("ES", SPAIN_COST), DEFAULT_COST,
                WINDOW, WINDOW_CAP, DAY_CAP, 0, null, 0, null);

        final var policy = new SmsConfiguration().smsCostPolicy(properties);

        assertTrue(policy.isCountryAllowed("ES"));
        assertFalse(policy.isCountryAllowed("US"));
        assertEquals(SPAIN_COST, policy.costMicros("ES"));
        assertEquals(DEFAULT_COST, policy.costMicros("FR"));
        assertEquals(WINDOW, policy.window());
        assertTrue(policy.isWithinWindowCap(WINDOW_CAP));
        assertFalse(policy.isWithinWindowCap(WINDOW_CAP + 1));
        assertTrue(policy.isWithinDailyCap(DAY_CAP));
        assertFalse(policy.isWithinDailyCap(DAY_CAP + 1));
    }
}
