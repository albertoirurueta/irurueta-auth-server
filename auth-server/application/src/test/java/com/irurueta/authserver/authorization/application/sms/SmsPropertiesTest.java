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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * Unit tests of {@link SmsProperties}.
 */
class SmsPropertiesTest {

    /** Binding prefix. */
    private static final String PREFIX = "authserver.sms";

    /** Default cost, in micros. */
    private static final long DEFAULT_COST = 50_000L;

    /** Default window cap, in micros. */
    private static final long WINDOW_CAP = 5_000_000L;

    /** Default day cap, in micros. */
    private static final long DAY_CAP = 20_000_000L;

    /** Configured cost of Spain. */
    private static final long SPAIN_COST = 70_000L;

    /** Configured code length. */
    private static final int LENGTH = 8;

    /** Default code length. */
    private static final int DEFAULT_LENGTH = 6;

    /** Default validity of the verification code. */
    private static final Duration DEFAULT_CODE_TTL = Duration.ofMinutes(10);

    /** Default attempts. */
    private static final int DEFAULT_ATTEMPTS = 5;

    /**
     * Verifies that nothing configured yields the defaults.
     */
    @Test
    void constructor_whenNothingIsConfigured_appliesDefaults() {
        final var properties = new SmsProperties(null, null, null, DEFAULT_COST, null, WINDOW_CAP, DAY_CAP, 0, null,
                0, null);

        assertEquals("US", properties.defaultRegion());
        assertEquals(Set.of("US", "ES", "GB"), properties.allowedCountries());
        assertEquals(Map.of(), properties.costPerCountryMicros());
        assertEquals(Duration.ofHours(1), properties.window());
        assertEquals(DEFAULT_LENGTH, properties.verificationCodeLength());
        assertEquals(DEFAULT_CODE_TTL, properties.verificationCodeTtl());
        assertEquals(DEFAULT_ATTEMPTS, properties.verificationMaxAttempts());
        assertEquals(Duration.ofDays(2), properties.ledgerRetention());
    }

    /**
     * Verifies that configured values are kept.
     */
    @Test
    void constructor_whenValuesAreConfigured_keepsThem() {
        final var properties = new SmsProperties("ES", Set.of("ES"), Map.of("ES", SPAIN_COST), 1L,
                Duration.ofMinutes(30), 2L, 3L, LENGTH, Duration.ofMinutes(5), 2, Duration.ofDays(1));

        assertEquals("ES", properties.defaultRegion());
        assertEquals(Set.of("ES"), properties.allowedCountries());
        assertEquals(Map.of("ES", SPAIN_COST), properties.costPerCountryMicros());
        assertEquals(LENGTH, properties.verificationCodeLength());
        assertEquals(Duration.ofDays(1), properties.ledgerRetention());
    }

    /**
     * Verifies that an invalid region is rejected wherever it appears.
     */
    @Test
    void constructor_whenARegionIsInvalid_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties("es", null, null, 0L, null, 0L, 0L, 0, null, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, Set.of("Spain"), null, 0L, null, 0L, 0L, 0, null, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, Map.of("x", 1L), 0L, null, 0L, 0L, 0, null, 0, null));
    }

    /**
     * Verifies that a negative cost or cap is rejected.
     */
    @Test
    void constructor_whenAnAmountIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, Map.of("ES", -1L), 0L, null, 0L, 0L, 0, null, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, null, -1L, null, 0L, 0L, 0, null, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, null, 0L, null, -1L, 0L, 0, null, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, null, 0L, null, 0L, -1L, 0, null, 0, null));
    }

    /**
     * Verifies that a negative number or duration is rejected.
     */
    @Test
    void constructor_whenANumberOrDurationIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, null, 0L, null, 0L, 0L, -1, null, 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, null, 0L, null, 0L, 0L, 0, null, -1, null));
        assertThrows(IllegalArgumentException.class,
                () -> new SmsProperties(null, null, null, 0L, Duration.ofHours(-1), 0L, 0L, 0, null, 0, null));
    }

    /**
     * Verifies that a ledger retention shorter than a day is rejected, since it would break the daily cap.
     */
    @Test
    void constructor_whenRetentionIsShorterThanADay_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsProperties(null, null, null, 0L, null, 0L, 0L, 0,
                null, 0, Duration.ofDays(1).minusSeconds(1)));
    }

    /**
     * Verifies that the binder builds the defaults when nothing is configured.
     */
    @Test
    void binding_whenNothingIsConfigured_buildsDefaults() {
        final var properties = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate(PREFIX, SmsProperties.class);

        assertEquals("US", properties.defaultRegion());
        assertEquals(Set.of("US", "ES", "GB"), properties.allowedCountries());
        assertEquals(DEFAULT_COST, properties.defaultCostMicros());
        assertEquals(WINDOW_CAP, properties.windowCapMicros());
        assertEquals(DAY_CAP, properties.dailyCapMicros());
        assertEquals(Duration.ofHours(1), properties.window());
    }

    /**
     * Verifies that the binder reads the configured values, including the cost map.
     */
    @Test
    void binding_whenValuesAreConfigured_readsThem() {
        final var properties = new Binder(new MapConfigurationPropertySource(Map.of(
                PREFIX + ".default-region", "GB",
                PREFIX + ".allowed-countries", "GB,ES",
                PREFIX + ".cost-per-country-micros.ES", "70000")))
                .bindOrCreate(PREFIX, SmsProperties.class);

        assertEquals("GB", properties.defaultRegion());
        assertEquals(Set.of("GB", "ES"), properties.allowedCountries());
        assertEquals(Map.of("ES", SPAIN_COST), properties.costPerCountryMicros());
    }
}
