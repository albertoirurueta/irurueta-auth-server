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

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;
import java.util.UUID;

/**
 * A numeric one-time code that was issued to a user. Only the hash of the code is kept. The binding identifier is
 * held by the browser that requested the code (in its session), so the code only works there.
 *
 * @param id        identifier of the stored code.
 * @param username  user name of the account the code was issued to.
 * @param channel   channel the code was delivered through.
 * @param purpose   what the code is used for.
 * @param codeHash  hash of the code, never the code itself.
 * @param bindingId identifier binding the code to the requesting browser session.
 * @param attempts  number of wrong submissions so far.
 * @param expiresAt instant after which the code is no longer valid.
 * @param createdAt instant at which the code was issued.
 */
public record OneTimeCode(
        UUID id,
        String username,
        OttChannel channel,
        OttPurpose purpose,
        String codeHash,
        String bindingId,
        int attempts,
        Instant expiresAt,
        Instant createdAt) {

    /**
     * Validates the code.
     *
     * @throws IllegalArgumentException if the id, channel, purpose or an instant is missing, the user name, hash or
     *                                  binding is blank, the attempts are negative or the code expires before it was
     *                                  created.
     */
    public OneTimeCode {
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        requireText(username, "username");
        if (channel == null) {
            throw new IllegalArgumentException("channel must not be null");
        }
        if (purpose == null) {
            throw new IllegalArgumentException("purpose must not be null");
        }
        requireText(codeHash, "codeHash");
        requireText(bindingId, "bindingId");
        if (attempts < 0) {
            throw new IllegalArgumentException("attempts must not be negative");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt must not be null");
        }
        if (createdAt == null) {
            throw new IllegalArgumentException("createdAt must not be null");
        }
        if (expiresAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("expiresAt must not be before createdAt");
        }
    }

    /**
     * Tells whether the code has expired.
     *
     * @param now current instant.
     * @return {@code true} when the code expires at or before {@code now}.
     */
    public boolean isExpiredAt(final Instant now) {
        return !expiresAt.isAfter(now);
    }
}
