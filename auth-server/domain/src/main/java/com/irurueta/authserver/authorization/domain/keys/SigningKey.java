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

package com.irurueta.authserver.authorization.domain.keys;

import static com.irurueta.authserver.authorization.domain.Preconditions.requireText;

import java.time.Instant;

/**
 * An asymmetric key pair used to sign tokens. The private half is only ever kept encrypted.
 *
 * @param kid                 key identifier, published in the {@code kid} header of signed tokens.
 * @param alg                 JWS algorithm the key is used with, for example {@code RS256}.
 * @param publicJwk           the public key as a JSON Web Key.
 * @param encryptedPrivateJwk the private key as a JSON Web Key, encrypted.
 * @param status              lifecycle state.
 * @param createdAt           instant at which the key was generated.
 * @param activatedAt         instant at which the key started signing; {@code null} until then.
 * @param retiredAt           instant at which the key stopped signing; {@code null} until then.
 */
public record SigningKey(
        String kid, String alg, String publicJwk, String encryptedPrivateJwk, SigningKeyStatus status,
        Instant createdAt, Instant activatedAt, Instant retiredAt) {

    /**
     * Validates the key.
     *
     * @throws IllegalArgumentException if a text is null or blank, or the status or creation instant is null.
     */
    public SigningKey {
        requireText(kid, "kid");
        requireText(alg, "alg");
        requireText(publicJwk, "publicJwk");
        requireText(encryptedPrivateJwk, "encryptedPrivateJwk");
        if (status == null || createdAt == null) {
            throw new IllegalArgumentException("status and createdAt must not be null");
        }
    }

    /**
     * Creates the key as it is once it starts signing.
     *
     * @param now instant at which it starts signing.
     * @return the active key.
     */
    public SigningKey activate(final Instant now) {
        return new SigningKey(kid, alg, publicJwk, encryptedPrivateJwk, SigningKeyStatus.ACTIVE, createdAt, now,
                retiredAt);
    }

    /**
     * Creates the key as it is once it stops signing.
     *
     * @param now instant at which it stops signing.
     * @return the retired key.
     */
    public SigningKey retire(final Instant now) {
        return new SigningKey(kid, alg, publicJwk, encryptedPrivateJwk, SigningKeyStatus.RETIRED, createdAt,
                activatedAt, now);
    }
}
