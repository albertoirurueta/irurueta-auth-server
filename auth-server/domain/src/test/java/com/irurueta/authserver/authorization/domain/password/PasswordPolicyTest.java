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

package com.irurueta.authserver.authorization.domain.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PasswordPolicy}.
 */
class PasswordPolicyTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Policy under test. */
    private final PasswordPolicy policy = new PasswordPolicy();

    /**
     * Verifies that a long enough password without composition is accepted.
     */
    @Test
    void violations_whenPasswordIsLongEnough_isEmpty() {
        assertTrue(policy.violations(USERNAME, "a".repeat(PasswordPolicy.MIN_LENGTH)).isEmpty());
        assertTrue(policy.isValid(USERNAME, "a".repeat(PasswordPolicy.MAX_LENGTH)));
    }

    /**
     * Verifies that a short password is rejected.
     */
    @Test
    void violations_whenPasswordIsShort_reportsTooShort() {
        final var password = "a".repeat(PasswordPolicy.MIN_LENGTH - 1);

        assertEquals(List.of(PasswordViolation.TOO_SHORT), policy.violations(USERNAME, password));
        assertFalse(policy.isValid(USERNAME, password));
    }

    /**
     * Verifies that a missing password is treated as empty.
     */
    @Test
    void violations_whenPasswordIsNull_reportsTooShort() {
        assertEquals(List.of(PasswordViolation.TOO_SHORT), policy.violations(USERNAME, null));
    }

    /**
     * Verifies that a long password is rejected.
     */
    @Test
    void violations_whenPasswordIsTooLong_reportsTooLong() {
        final var password = "a".repeat(PasswordPolicy.MAX_LENGTH + 1);

        assertEquals(List.of(PasswordViolation.TOO_LONG), policy.violations(USERNAME, password));
    }

    /**
     * Verifies that a password containing the username, in any case, is rejected.
     */
    @Test
    void violations_whenPasswordContainsUsername_reportsContainsUsername() {
        final var password = "xx-ALICE-" + "y".repeat(PasswordPolicy.MIN_LENGTH);

        assertEquals(List.of(PasswordViolation.CONTAINS_USERNAME), policy.violations(USERNAME, password));
    }

    /**
     * Verifies that the username rule is skipped when the username is unknown or blank.
     */
    @Test
    void violations_whenUsernameIsMissing_skipsUsernameRule() {
        final var password = "alice" + "y".repeat(PasswordPolicy.MIN_LENGTH);

        assertTrue(policy.violations(null, password).isEmpty());
        assertTrue(policy.violations(" ", password).isEmpty());
    }

    /**
     * Verifies that several broken rules are all reported.
     */
    @Test
    void violations_whenSeveralRulesBreak_reportsAll() {
        assertEquals(List.of(PasswordViolation.TOO_SHORT, PasswordViolation.CONTAINS_USERNAME),
                policy.violations(USERNAME, USERNAME));
    }
}
