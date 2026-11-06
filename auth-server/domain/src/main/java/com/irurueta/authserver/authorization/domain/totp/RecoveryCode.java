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
package com.irurueta.authserver.authorization.domain.totp;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;
import java.util.UUID;

/**
 * A single-use code that replaces the second factor when the authenticator is lost. Only its hash is kept.
 *
 * @param id         unique identifier of the code.
 * @param userId     identifier of the user the code belongs to.
 * @param hashedCode hash of the code.
 * @param usedAt     instant at which the code was spent; {@code null} while it is unused.
 */
public record RecoveryCode(UUID id, UUID userId, String hashedCode, Instant usedAt) {

    /**
     * Validates the code.
     *
     * @throws IllegalArgumentException if an identifier is missing or the hash is blank.
     */
    public RecoveryCode {
        if (id == null || userId == null) {
            throw new IllegalArgumentException("id and userId must not be null");
        }
        requireText(hashedCode, "hashedCode");
    }

    /**
     * Tells whether the code has been spent.
     *
     * @return {@code true} when it has a use instant.
     */
    public boolean isUsed() {
        return usedAt != null;
    }
}
