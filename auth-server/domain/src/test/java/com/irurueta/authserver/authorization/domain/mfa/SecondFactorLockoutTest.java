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
package com.irurueta.authserver.authorization.domain.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SecondFactorLockout}.
 */
class SecondFactorLockoutTest {

    /** Instant used as the end of a lock. */
    private static final Instant UNTIL = Instant.parse("2026-01-01T00:15:00Z");

    /** Failed attempts used by the tests. */
    private static final int FAILED = 5;

    /**
     * Verifies that a negative counter is rejected.
     */
    @Test
    void constructor_whenCounterIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SecondFactorLockout(-1, null));
    }

    /**
     * Verifies that the clean state has no failures and no lock.
     */
    @Test
    void none_returnsCleanState() {
        final var state = SecondFactorLockout.none();

        assertEquals(0, state.failedCount());
        assertNull(state.lockedUntil());
        assertFalse(state.isLocked(UNTIL));
    }

    /**
     * Verifies that the lock holds before its end.
     */
    @Test
    void isLocked_whenBeforeLockEnd_returnsTrue() {
        assertTrue(new SecondFactorLockout(FAILED, UNTIL).isLocked(UNTIL.minusSeconds(1)));
    }

    /**
     * Verifies that the lock is over at its end.
     */
    @Test
    void isLocked_whenAtLockEnd_returnsFalse() {
        assertFalse(new SecondFactorLockout(FAILED, UNTIL).isLocked(UNTIL));
    }
}
