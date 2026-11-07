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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * Unit tests of {@link OttProperties}.
 */
class OttPropertiesTest {

    /** Binding prefix. */
    private static final String PREFIX = "authserver.ott";

    /** Configured code length. */
    private static final int LENGTH = 8;

    /** Configured attempts. */
    private static final int ATTEMPTS = 3;

    /** Configured code validity. */
    private static final Duration CODE_TTL = Duration.ofMinutes(3);

    /** Configured link validity. */
    private static final Duration LINK_TTL = Duration.ofMinutes(7);

    /** Default code length. */
    private static final int DEFAULT_LENGTH = 6;

    /** Default attempts. */
    private static final int DEFAULT_ATTEMPTS = 5;

    /** Default code validity, in minutes. */
    private static final long DEFAULT_CODE_MINUTES = 10L;

    /** Default link validity, in minutes. */
    private static final long DEFAULT_LINK_MINUTES = 15L;

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var properties = new OttProperties(LENGTH, CODE_TTL, LINK_TTL, ATTEMPTS);

        assertEquals(LENGTH, properties.codeLength());
        assertEquals(CODE_TTL, properties.codeTtl());
        assertEquals(LINK_TTL, properties.linkTtl());
        assertEquals(ATTEMPTS, properties.maxAttempts());
    }

    /**
     * Verifies that missing or zero values take their defaults.
     */
    @Test
    void constructor_whenValuesAreMissingOrZero_appliesDefaults() {
        final var properties = new OttProperties(0, null, Duration.ZERO, 0);

        assertEquals(DEFAULT_LENGTH, properties.codeLength());
        assertEquals(Duration.ofMinutes(DEFAULT_CODE_MINUTES), properties.codeTtl());
        assertEquals(Duration.ofMinutes(DEFAULT_LINK_MINUTES), properties.linkTtl());
        assertEquals(DEFAULT_ATTEMPTS, properties.maxAttempts());
    }

    /**
     * Verifies that a negative number is rejected.
     */
    @Test
    void constructor_whenANumberIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OttProperties(-1, CODE_TTL, LINK_TTL, ATTEMPTS));
        assertThrows(IllegalArgumentException.class, () -> new OttProperties(LENGTH, CODE_TTL, LINK_TTL, -1));
    }

    /**
     * Verifies that a negative duration is rejected.
     */
    @Test
    void constructor_whenADurationIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new OttProperties(LENGTH, CODE_TTL.negated(), LINK_TTL, ATTEMPTS));
        assertThrows(IllegalArgumentException.class,
                () -> new OttProperties(LENGTH, CODE_TTL, LINK_TTL.negated(), ATTEMPTS));
    }

    /**
     * Verifies that the binder builds the defaults when nothing is configured.
     */
    @Test
    void binding_whenNothingIsConfigured_buildsDefaults() {
        final var properties = new Binder(new MapConfigurationPropertySource(Map.of()))
                .bindOrCreate(PREFIX, OttProperties.class);

        assertEquals(DEFAULT_LENGTH, properties.codeLength());
        assertEquals(Duration.ofMinutes(DEFAULT_CODE_MINUTES), properties.codeTtl());
        assertEquals(Duration.ofMinutes(DEFAULT_LINK_MINUTES), properties.linkTtl());
        assertEquals(DEFAULT_ATTEMPTS, properties.maxAttempts());
    }

    /**
     * Verifies that the binder reads the configured values.
     */
    @Test
    void binding_whenValuesAreConfigured_readsThem() {
        final var properties = new Binder(new MapConfigurationPropertySource(
                Map.of(PREFIX + ".code-length", "8", PREFIX + ".code-ttl", "PT3M", PREFIX + ".max-attempts", "3")))
                .bindOrCreate(PREFIX, OttProperties.class);

        assertEquals(LENGTH, properties.codeLength());
        assertEquals(CODE_TTL, properties.codeTtl());
        assertEquals(ATTEMPTS, properties.maxAttempts());
    }
}
