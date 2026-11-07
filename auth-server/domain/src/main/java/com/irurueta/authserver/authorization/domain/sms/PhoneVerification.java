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

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;
import java.util.UUID;

/**
 * A pending verification of a phone number: the code that was sent to it, hashed, until the user types it.
 *
 * @param userId    identifier of the user verifying the number.
 * @param phone     the number being verified.
 * @param codeHash  hash of the code sent, never the code itself.
 * @param attempts  number of wrong submissions so far.
 * @param expiresAt instant after which the code is no longer valid.
 */
public record PhoneVerification(UUID userId, PhoneNumber phone, String codeHash, int attempts, Instant expiresAt) {

    /**
     * Validates the verification.
     *
     * @throws IllegalArgumentException if the user, number or expiry is missing, the hash is blank or the attempts
     *                                  are negative.
     */
    public PhoneVerification {
        if (userId == null) {
            throw new IllegalArgumentException("userId must not be null");
        }
        if (phone == null) {
            throw new IllegalArgumentException("phone must not be null");
        }
        requireText(codeHash, "codeHash");
        if (attempts < 0) {
            throw new IllegalArgumentException("attempts must not be negative");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt must not be null");
        }
    }

    /**
     * Tells whether the verification has expired.
     *
     * @param now current instant.
     * @return {@code true} when it expires at or before {@code now}.
     */
    public boolean isExpiredAt(final Instant now) {
        return !expiresAt.isAfter(now);
    }
}
