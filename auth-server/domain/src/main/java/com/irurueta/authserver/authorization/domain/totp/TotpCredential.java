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

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * The TOTP credential of one user. The secret is only ever held encrypted.
 *
 * @param userId          identifier of the user the credential belongs to.
 * @param encryptedSecret the secret, encrypted at rest; copied on the way in and on the way out.
 * @param confirmed       whether the user proved possession by entering a first valid code.
 * @param lastUsedStep    time step of the last accepted code, or {@link #NEVER_USED}; later codes must be newer.
 * @param createdAt       instant at which the credential was created.
 */
public record TotpCredential(
        UUID userId, byte[] encryptedSecret, boolean confirmed, long lastUsedStep, Instant createdAt) {

    /** Value of the last used step of a credential that has not accepted any code yet. */
    public static final long NEVER_USED = -1L;

    /**
     * Validates the credential and copies the secret.
     *
     * @throws IllegalArgumentException if the user, the secret or the creation instant is missing or empty, or the
     *                                  step is lower than {@link #NEVER_USED}.
     */
    public TotpCredential {
        if (userId == null || createdAt == null) {
            throw new IllegalArgumentException("userId and createdAt must not be null");
        }
        if (encryptedSecret == null || encryptedSecret.length == 0) {
            throw new IllegalArgumentException("encryptedSecret must not be empty");
        }
        if (lastUsedStep < NEVER_USED) {
            throw new IllegalArgumentException("lastUsedStep must not be lower than " + NEVER_USED);
        }
        encryptedSecret = encryptedSecret.clone();
    }

    /**
     * Gives the encrypted secret.
     *
     * @return a copy of the encrypted secret.
     */
    @Override
    public byte[] encryptedSecret() {
        return encryptedSecret.clone();
    }

    /**
     * Compares credentials by value, comparing the secret by content.
     *
     * @param other the object to compare with.
     * @return {@code true} when every component is equal.
     */
    @Override
    public boolean equals(final Object other) {
        return other instanceof TotpCredential credential
                && userId.equals(credential.userId)
                && confirmed == credential.confirmed
                && lastUsedStep == credential.lastUsedStep
                && createdAt.equals(credential.createdAt)
                && Arrays.equals(encryptedSecret, credential.encryptedSecret);
    }

    /**
     * Computes a hash consistent with {@link #equals(Object)}.
     *
     * @return the hash code.
     */
    @Override
    public int hashCode() {
        return Objects.hash(userId, confirmed, lastUsedStep, createdAt, Arrays.hashCode(encryptedSecret));
    }

    /**
     * Describes the credential without its secret.
     *
     * @return a text that never includes the secret.
     */
    @Override
    public String toString() {
        return "TotpCredential[userId=" + userId + ", confirmed=" + confirmed + ", lastUsedStep=" + lastUsedStep
                + ", createdAt=" + createdAt + "]";
    }
}
