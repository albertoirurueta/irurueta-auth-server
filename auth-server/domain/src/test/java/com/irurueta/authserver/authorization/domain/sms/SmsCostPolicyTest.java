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
package com.irurueta.authserver.authorization.domain.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SmsCostPolicy}.
 */
class SmsCostPolicyTest {

    /** Cost of a message to Spain used by the tests. */
    private static final long SPAIN_COST = 70_000L;

    /** Default cost used by the tests. */
    private static final long DEFAULT_COST = 50_000L;

    /** Window used by the tests. */
    private static final Duration WINDOW = Duration.ofMinutes(10);

    /** Window budget used by the tests. */
    private static final long WINDOW_CAP = 1_000_000L;

    /** Daily budget used by the tests. */
    private static final long DAILY_CAP = 5_000_000L;

    /**
     * Verifies that only the allowed countries pass.
     */
    @Test
    void isCountryAllowed_whenCountryIsAllowedOrNot_reflectsAllowList() {
        final var policy = create();

        assertTrue(policy.isCountryAllowed("ES"));
        assertFalse(policy.isCountryAllowed("FR"));
        assertFalse(policy.isCountryAllowed(null));
    }

    /**
     * Verifies that an empty allow list allows nothing.
     */
    @Test
    void isCountryAllowed_whenAllowListIsEmpty_returnsFalse() {
        final var policy = new SmsCostPolicy(Set.of(), Map.of(), DEFAULT_COST, WINDOW, WINDOW_CAP, DAILY_CAP);

        assertFalse(policy.isCountryAllowed("ES"));
    }

    /**
     * Verifies the cost of a country with its own cost and one without.
     */
    @Test
    void costMicros_whenCountryHasOwnCostOrNot_returnsOwnOrDefault() {
        final var policy = create();

        assertEquals(SPAIN_COST, policy.costMicros("ES"));
        assertEquals(DEFAULT_COST, policy.costMicros("US"));
    }

    /**
     * Verifies the window.
     */
    @Test
    void window_whenCreated_returnsConfiguredWindow() {
        assertEquals(WINDOW, create().window());
    }

    /**
     * Verifies that the caps handed to the ledger carry the windows and budgets of the policy.
     */
    @Test
    void windowCapAndDailyCap_whenCreated_carryTheConfiguredBudgets() {
        final var policy = create();

        assertEquals(new SmsSpendCap(WINDOW, WINDOW_CAP), policy.windowCap());
        assertEquals(new SmsSpendCap(SmsCostPolicy.DAY, DAILY_CAP), policy.dailyCap());
    }

    /**
     * Verifies the window budget boundary.
     */
    @Test
    void isWithinWindowCap_whenBelowAtAndAboveCap_reflectsBoundary() {
        final var policy = create();

        assertTrue(policy.isWithinWindowCap(WINDOW_CAP - 1));
        assertTrue(policy.isWithinWindowCap(WINDOW_CAP));
        assertFalse(policy.isWithinWindowCap(WINDOW_CAP + 1));
    }

    /**
     * Verifies the daily budget boundary.
     */
    @Test
    void isWithinDailyCap_whenBelowAtAndAboveCap_reflectsBoundary() {
        final var policy = create();

        assertTrue(policy.isWithinDailyCap(DAILY_CAP - 1));
        assertTrue(policy.isWithinDailyCap(DAILY_CAP));
        assertFalse(policy.isWithinDailyCap(DAILY_CAP + 1));
    }

    /**
     * Verifies that missing collections are rejected.
     */
    @Test
    void constructor_whenCollectionsAreNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(null, Map.of(), DEFAULT_COST, WINDOW, WINDOW_CAP, DAILY_CAP));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(Set.of(), null, DEFAULT_COST, WINDOW, WINDOW_CAP, DAILY_CAP));
    }

    /**
     * Verifies that a non-positive window is rejected.
     */
    @Test
    void constructor_whenWindowIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(Set.of(), Map.of(), DEFAULT_COST, null, WINDOW_CAP, DAILY_CAP));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(Set.of(), Map.of(), DEFAULT_COST, Duration.ZERO, WINDOW_CAP, DAILY_CAP));
        assertThrows(IllegalArgumentException.class, () -> new SmsCostPolicy(Set.of(), Map.of(), DEFAULT_COST,
                Duration.ofSeconds(-1), WINDOW_CAP, DAILY_CAP));
    }

    /**
     * Verifies that negative costs and caps are rejected.
     */
    @Test
    void constructor_whenCostOrCapIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(Set.of(), Map.of(), -1, WINDOW, WINDOW_CAP, DAILY_CAP));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(Set.of(), Map.of(), DEFAULT_COST, WINDOW, -1, DAILY_CAP));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(Set.of(), Map.of(), DEFAULT_COST, WINDOW, WINDOW_CAP, -1));
    }

    /**
     * Verifies that an allowed country that is not an upper-case alpha-2 code is rejected.
     */
    @Test
    void constructor_whenAllowedCountryIsMalformed_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SmsCostPolicy(Set.of("es"), Map.of(), DEFAULT_COST, WINDOW, WINDOW_CAP, DAILY_CAP));
    }

    /**
     * Verifies that a malformed country or a negative cost in the cost map is rejected.
     */
    @Test
    void constructor_whenCostEntryIsInvalid_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsCostPolicy(Set.of(), Map.of("Spain", 1L),
                DEFAULT_COST, WINDOW, WINDOW_CAP, DAILY_CAP));
        assertThrows(IllegalArgumentException.class, () -> new SmsCostPolicy(Set.of(), Map.of("ES", -1L),
                DEFAULT_COST, WINDOW, WINDOW_CAP, DAILY_CAP));
        final var withNull = new HashMap<String, Long>();
        withNull.put("ES", null);
        assertThrows(IllegalArgumentException.class, () -> new SmsCostPolicy(Set.of(), withNull,
                DEFAULT_COST, WINDOW, WINDOW_CAP, DAILY_CAP));
    }

    /**
     * Creates a valid policy allowing Spain and the United States.
     *
     * @return the policy.
     */
    private static SmsCostPolicy create() {
        return new SmsCostPolicy(Set.of("ES", "US"), Map.of("ES", SPAIN_COST), DEFAULT_COST, WINDOW, WINDOW_CAP,
                DAILY_CAP);
    }
}
