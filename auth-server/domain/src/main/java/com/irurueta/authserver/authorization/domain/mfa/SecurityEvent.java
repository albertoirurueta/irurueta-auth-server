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

import static com.irurueta.authserver.authorization.domain.Preconditions.requireTextIfPresent;

import java.time.Instant;
import java.util.UUID;

/**
 * An authentication event kept for audit. It never carries a credential, a code or a token.
 *
 * @param type       kind of event.
 * @param userId     identifier of the user concerned, or {@code null} when the event cannot be tied to an account.
 * @param username   name that was presented, or {@code null}.
 * @param detail     short description of the circumstances, or {@code null}.
 * @param occurredAt instant of the event.
 */
public record SecurityEvent(
        SecurityEventType type, UUID userId, String username, String detail, Instant occurredAt) {

    /**
     * Validates the event.
     *
     * @throws IllegalArgumentException if the type or the instant is missing, or an optional text is blank.
     */
    public SecurityEvent {
        if (type == null || occurredAt == null) {
            throw new IllegalArgumentException("type and occurredAt must not be null");
        }
        requireTextIfPresent(username, "username");
        requireTextIfPresent(detail, "detail");
    }
}
