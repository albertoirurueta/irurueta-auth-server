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

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Port that keeps the failed second-factor attempts of each user, so that a lockout survives restarts and is shared by
 * every instance of the server.
 */
public interface SecondFactorAttemptRepository {

    /**
     * Reads the state of a user.
     *
     * @param userId identifier of the user.
     * @return the state; {@link SecondFactorLockout#none()} when nothing was recorded.
     */
    SecondFactorLockout find(UUID userId);

    /**
     * Reads the state of a user and locks it until the end of the current transaction, creating a clean state first
     * when nothing was recorded, so that concurrent verifications of the same user's second factor run one after the
     * other instead of all passing the lockout check before any of their failures is counted.
     *
     * @param userId identifier of the user.
     * @return the state; {@link SecondFactorLockout#none()} when nothing was recorded.
     */
    SecondFactorLockout lockForUpdate(UUID userId);

    /**
     * Records one failed attempt and, when the counter reaches the maximum, locks the second factor.
     *
     * @param userId      identifier of the user.
     * @param maxAttempts consecutive failures that trigger the lock.
     * @param lockout     how long the lock lasts.
     * @param now         current instant.
     * @return the state after the failure.
     */
    SecondFactorLockout recordFailure(UUID userId, int maxAttempts, Duration lockout, Instant now);

    /**
     * Clears the counter and any lock, after a successful verification.
     *
     * @param userId identifier of the user.
     */
    void reset(UUID userId);
}
