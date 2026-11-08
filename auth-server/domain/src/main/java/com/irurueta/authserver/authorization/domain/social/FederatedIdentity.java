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
package com.irurueta.authserver.authorization.domain.social;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;
import static com.irurueta.authserver.authorization.domain.Preconditions.requireTextIfPresent;

import java.time.Instant;
import java.util.UUID;

/**
 * An identity of an external provider linked to a local account: the account is reached by presenting the provider's
 * stable subject, never by its e-mail address, which a provider may change.
 *
 * @param id          identifier of the link.
 * @param userId      identifier of the local account (the {@code users} row).
 * @param provider    provider that holds the identity.
 * @param subject     stable identifier the provider assigned to the user (the {@code sub} claim, or the numeric id of
 *                    GitHub).
 * @param email       e-mail address the provider reported when the identity was last used, or {@code null}.
 * @param linkedAt    instant at which the identity was linked.
 * @param lastLoginAt instant of the last sign-in with it, or {@code null} when it has not been used since it was
 *                    linked.
 */
public record FederatedIdentity(
        UUID id,
        UUID userId,
        IdentityProvider provider,
        String subject,
        String email,
        Instant linkedAt,
        Instant lastLoginAt) {

    /**
     * Validates the identity.
     *
     * @throws IllegalArgumentException if the id, the account, the provider or the link instant is missing, the
     *                                  subject is blank, or the e-mail address is present and blank.
     */
    public FederatedIdentity {
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        if (userId == null) {
            throw new IllegalArgumentException("userId must not be null");
        }
        if (provider == null) {
            throw new IllegalArgumentException("provider must not be null");
        }
        requireText(subject, "subject");
        requireTextIfPresent(email, "email");
        if (linkedAt == null) {
            throw new IllegalArgumentException("linkedAt must not be null");
        }
    }
}
