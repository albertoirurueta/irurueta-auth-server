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

package com.irurueta.authserver.authorization.domain.clientauth;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;

/**
 * One presentation of a client assertion: which client presented which JWT identifier, and until when the assertion
 * is valid (after that instant the identifier no longer needs to be remembered).
 *
 * @param clientId  identifier of the client that authenticated with the assertion.
 * @param jti       the {@code jti} claim of the assertion.
 * @param expiresAt instant at which the assertion expires.
 */
public record ClientAssertionUse(String clientId, String jti, Instant expiresAt) {

    /**
     * Validates the components.
     *
     * @throws IllegalArgumentException if the client identifier or the {@code jti} is blank, or the expiry is
     *                                  {@code null}.
     */
    public ClientAssertionUse {
        requireText(clientId, "clientId");
        requireText(jti, "jti");
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt must not be null");
        }
    }
}
