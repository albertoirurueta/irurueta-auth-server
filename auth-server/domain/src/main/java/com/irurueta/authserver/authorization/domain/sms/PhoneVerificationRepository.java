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

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Port that stores the pending phone verification of each user, with the code hashed. An implementation never returns
 * {@code null}.
 */
public interface PhoneVerificationRepository {

    /**
     * Stores the pending verification of a user, replacing the one it had.
     *
     * @param verification the verification.
     */
    void save(PhoneVerification verification);

    /**
     * Finds the pending verification of a user.
     *
     * @param userId identifier of the user.
     * @return the verification, or empty when there is none.
     */
    Optional<PhoneVerification> findByUserId(UUID userId);

    /**
     * Counts a wrong submission, in one atomic step.
     *
     * @param userId identifier of the user.
     * @return the number of attempts after the increment, or {@code 0} when there is no pending verification.
     */
    int incrementAttempts(UUID userId);

    /**
     * Removes the pending verification of a user.
     *
     * @param userId identifier of the user.
     */
    void deleteByUserId(UUID userId);

    /**
     * Deletes every pending verification that has expired.
     *
     * @param now current instant.
     * @return the number of deleted verifications.
     */
    int deleteExpired(Instant now);
}
