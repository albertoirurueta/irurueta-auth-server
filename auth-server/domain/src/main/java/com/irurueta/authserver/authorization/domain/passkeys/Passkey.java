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
package com.irurueta.authserver.authorization.domain.passkeys;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;

/**
 * A passkey (WebAuthn credential) registered by a user. Only the data a user manages is modelled; the public key and
 * attestation stay in the framework's store.
 *
 * @param id             credential identifier, as the unpadded base64url text Spring Security stores.
 * @param userId         WebAuthn user handle of the owner, as the unpadded base64url text Spring Security stores.
 * @param label          name the user gave to the passkey.
 * @param createdAt      instant at which the passkey was registered.
 * @param lastUsedAt     instant of the last sign-in with it, or {@code null} when it has never been used.
 * @param signatureCount signature counter reported by the authenticator at its last use.
 * @param backupEligible whether the authenticator allows the credential to be backed up (synced).
 * @param backedUp       whether the credential is currently backed up.
 */
public record Passkey(
        String id,
        String userId,
        String label,
        Instant createdAt,
        Instant lastUsedAt,
        long signatureCount,
        boolean backupEligible,
        boolean backedUp) {

    /**
     * Validates the passkey.
     *
     * @throws IllegalArgumentException if the id, owner or label is blank, the creation instant is missing, or the
     *                                  signature counter is negative.
     */
    public Passkey {
        requireText(id, "id");
        requireText(userId, "userId");
        requireText(label, "label");
        if (createdAt == null) {
            throw new IllegalArgumentException("createdAt must not be null");
        }
        if (signatureCount < 0) {
            throw new IllegalArgumentException("signatureCount must not be negative");
        }
    }
}
