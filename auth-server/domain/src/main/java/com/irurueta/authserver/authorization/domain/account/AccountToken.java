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

package com.irurueta.authserver.authorization.domain.account;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;
import java.util.UUID;

/**
 * A single-use token that proves the right to perform one account operation. Only the hash of the token is kept; the
 * token itself exists in the e-mail sent to the user.
 *
 * @param id          unique identifier of the stored token.
 * @param userId      identifier of the account the token belongs to.
 * @param purpose     what the token allows, for example {@link #PURPOSE_PASSWORD_RESET}.
 * @param hashedToken hash of the token value.
 * @param expiresAt   instant after which the token cannot be consumed.
 * @param usedAt      instant at which the token was consumed; {@code null} while it is unused.
 */
public record AccountToken(
        UUID id, UUID userId, String purpose, String hashedToken, Instant expiresAt, Instant usedAt) {

    /** Purpose of the signed token that proves ownership of an e-mail address. */
    public static final String PURPOSE_EMAIL_VERIFICATION = "email_verification";

    /** Purpose of the single-use token that allows choosing a new password. */
    public static final String PURPOSE_PASSWORD_RESET = "password_reset";

    /**
     * Validates the token.
     *
     * @throws IllegalArgumentException if the id, user id, purpose, hash or expiry is missing or blank.
     */
    public AccountToken {
        if (id == null || userId == null) {
            throw new IllegalArgumentException("id and userId must not be null");
        }
        requireText(purpose, "purpose");
        requireText(hashedToken, "hashedToken");
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt must not be null");
        }
    }
}
