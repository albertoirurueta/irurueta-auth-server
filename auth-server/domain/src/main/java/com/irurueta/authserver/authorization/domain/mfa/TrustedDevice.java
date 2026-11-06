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

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;
import static com.irurueta.authserver.authorization.domain.Preconditions.requireTextIfPresent;

import java.time.Instant;
import java.util.UUID;

/**
 * A browser that a user chose to trust, which lets it skip the second factor (never the first) until it expires. Only
 * the hash of the device token is kept; the token itself lives in the browser's cookie.
 *
 * @param id               unique identifier of the device.
 * @param userId           identifier of the user who trusts it.
 * @param hashedToken      hash of the device token.
 * @param userAgentSummary short description of the browser, or {@code null}.
 * @param expiresAt        instant after which the device is no longer trusted.
 * @param createdAt        instant at which the device was trusted.
 */
public record TrustedDevice(
        UUID id, UUID userId, String hashedToken, String userAgentSummary, Instant expiresAt, Instant createdAt) {

    /**
     * Validates the device.
     *
     * @throws IllegalArgumentException if an identifier, an instant or the hash is missing, or the summary is blank.
     */
    public TrustedDevice {
        if (id == null || userId == null) {
            throw new IllegalArgumentException("id and userId must not be null");
        }
        requireText(hashedToken, "hashedToken");
        requireTextIfPresent(userAgentSummary, "userAgentSummary");
        if (expiresAt == null || createdAt == null) {
            throw new IllegalArgumentException("expiresAt and createdAt must not be null");
        }
    }

    /**
     * Tells whether the device is no longer trusted at an instant.
     *
     * @param now the instant to check.
     * @return {@code true} when the expiry has been reached.
     */
    public boolean isExpired(final Instant now) {
        return !now.isBefore(expiresAt);
    }
}
