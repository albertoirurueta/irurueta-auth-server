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

import java.time.Instant;

/**
 * The failed-attempt state of the second factor of one user.
 *
 * @param failedCount consecutive failed attempts, never negative.
 * @param lockedUntil instant until which the second factor is locked, or {@code null} when it is not locked.
 */
public record SecondFactorLockout(int failedCount, Instant lockedUntil) {

    /**
     * Validates the state.
     *
     * @throws IllegalArgumentException if the counter is negative.
     */
    public SecondFactorLockout {
        if (failedCount < 0) {
            throw new IllegalArgumentException("failedCount must not be negative");
        }
    }

    /**
     * Creates the state of a user with no failed attempts.
     *
     * @return the clean state.
     */
    public static SecondFactorLockout none() {
        return new SecondFactorLockout(0, null);
    }

    /**
     * Tells whether the second factor is locked at an instant.
     *
     * @param now the instant to check.
     * @return {@code true} when a lock exists and has not ended yet.
     */
    public boolean isLocked(final Instant now) {
        return lockedUntil != null && now.isBefore(lockedUntil);
    }
}
