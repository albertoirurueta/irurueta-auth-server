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

package com.irurueta.authserver.authorization.application.clientauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * Unit tests of {@link ClientAssertionProperties}.
 */
class ClientAssertionPropertiesTest {

    /** Binding prefix. */
    private static final String PREFIX = "authserver.client-assertion";

    /** Configured lifetime. */
    private static final Duration LIFETIME = Duration.ofMinutes(2);

    /** Default lifetime, in minutes. */
    private static final long DEFAULT_MINUTES = 5L;

    /** Default cron. */
    private static final String DEFAULT_CRON = "0 30 * * * *";

    /** Configured cron. */
    private static final String CRON = "0 0 * * * *";

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var properties = new ClientAssertionProperties(LIFETIME, new ClientAssertionProperties.Cleanup(CRON));

        assertEquals(LIFETIME, properties.maxLifetime());
        assertEquals(CRON, properties.cleanup().cron());
    }

    /**
     * Verifies that missing values take their defaults.
     */
    @Test
    void constructor_whenValuesAreMissing_appliesDefaults() {
        final var properties = new ClientAssertionProperties(null, null);

        assertEquals(Duration.ofMinutes(DEFAULT_MINUTES), properties.maxLifetime());
        assertEquals(DEFAULT_CRON, properties.cleanup().cron());
        assertEquals(DEFAULT_CRON, new ClientAssertionProperties.Cleanup(" ").cron());
    }

    /**
     * Verifies that a zero or negative lifetime is rejected.
     */
    @Test
    void constructor_whenLifetimeIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAssertionProperties(Duration.ZERO, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ClientAssertionProperties(Duration.ofSeconds(-1), null));
    }

    /**
     * Verifies that an invalid cron expression is rejected.
     */
    @Test
    void constructor_whenCronIsInvalid_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAssertionProperties.Cleanup("not a cron"));
    }

    /**
     * Verifies that the record binds from the property names and takes the defaults when nothing is set.
     */
    @Test
    void bind_whenPropertiesAreSetOrMissing_bindsValuesOrDefaults() {
        final var set = new Binder(new MapConfigurationPropertySource(Map.of(
                PREFIX + ".max-lifetime", "PT2M",
                PREFIX + ".cleanup.cron", CRON))).bind(PREFIX, ClientAssertionProperties.class).get();
        final var empty = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate(PREFIX, ClientAssertionProperties.class);

        assertEquals(LIFETIME, set.maxLifetime());
        assertEquals(CRON, set.cleanup().cron());
        assertEquals(Duration.ofMinutes(DEFAULT_MINUTES), empty.maxLifetime());
        assertEquals(DEFAULT_CRON, empty.cleanup().cron());
    }
}
