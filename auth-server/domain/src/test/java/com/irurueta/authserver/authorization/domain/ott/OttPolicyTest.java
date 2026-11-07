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
package com.irurueta.authserver.authorization.domain.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OttPolicy}.
 */
class OttPolicyTest {

    /** Code length used by the tests. */
    private static final int LENGTH = 6;

    /** Code lifetime used by the tests. */
    private static final Duration CODE_TTL = Duration.ofMinutes(10);

    /** Link lifetime used by the tests. */
    private static final Duration LINK_TTL = Duration.ofMinutes(15);

    /** Attempt limit used by the tests. */
    private static final int MAX_ATTEMPTS = 5;

    /**
     * Verifies that the configured values are exposed.
     */
    @Test
    void constructor_whenValuesAreValid_exposesThem() {
        final var policy = create();

        assertEquals(LENGTH, policy.codeLength());
        assertEquals(CODE_TTL, policy.ttl(OttKind.CODE));
        assertEquals(LINK_TTL, policy.ttl(OttKind.LINK));
        assertEquals(MAX_ATTEMPTS, policy.maxAttempts());
    }

    /**
     * Verifies that a non-positive length is rejected.
     */
    @Test
    void constructor_whenCodeLengthIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OttPolicy(0, CODE_TTL, LINK_TTL, MAX_ATTEMPTS));
    }

    /**
     * Verifies that a missing code lifetime is rejected.
     */
    @Test
    void constructor_whenCodeTtlIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OttPolicy(LENGTH, null, LINK_TTL, MAX_ATTEMPTS));
    }

    /**
     * Verifies that a zero link lifetime is rejected.
     */
    @Test
    void constructor_whenLinkTtlIsZero_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new OttPolicy(LENGTH, CODE_TTL, Duration.ZERO, MAX_ATTEMPTS));
    }

    /**
     * Verifies that a negative lifetime is rejected.
     */
    @Test
    void constructor_whenCodeTtlIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new OttPolicy(LENGTH, Duration.ofSeconds(-1), LINK_TTL, MAX_ATTEMPTS));
    }

    /**
     * Verifies that a non-positive attempt limit is rejected.
     */
    @Test
    void constructor_whenMaxAttemptsIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OttPolicy(LENGTH, CODE_TTL, LINK_TTL, 0));
    }

    /**
     * Verifies the attempt limit boundary.
     */
    @Test
    void isExhausted_whenBelowAtAndAboveLimit_reflectsBoundary() {
        final var policy = create();

        assertFalse(policy.isExhausted(MAX_ATTEMPTS - 1));
        assertTrue(policy.isExhausted(MAX_ATTEMPTS));
        assertTrue(policy.isExhausted(MAX_ATTEMPTS + 1));
    }

    /**
     * Creates a valid policy.
     *
     * @return the policy.
     */
    private static OttPolicy create() {
        return new OttPolicy(LENGTH, CODE_TTL, LINK_TTL, MAX_ATTEMPTS);
    }
}
