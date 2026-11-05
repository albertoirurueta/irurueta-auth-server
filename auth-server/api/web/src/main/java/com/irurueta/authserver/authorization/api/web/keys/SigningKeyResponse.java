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

package com.irurueta.authserver.authorization.api.web.keys;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/**
 * Public view of a signing key. The private half is never part of it.
 *
 * @param kid         key identifier.
 * @param alg         JWS algorithm.
 * @param status      lifecycle state ({@code NEXT}, {@code ACTIVE} or {@code RETIRED}).
 * @param createdAt   creation instant.
 * @param activatedAt instant at which it started signing, or {@code null}.
 * @param retiredAt   instant at which it stopped signing, or {@code null}.
 * @param publicJwk   the public key as a JSON Web Key.
 */
@Schema(description = "A signing key, without its private half")
public record SigningKeyResponse(
        String kid, String alg, String status, Instant createdAt, Instant activatedAt, Instant retiredAt,
        String publicJwk) {

    /**
     * Maps a key.
     *
     * @param key the key.
     * @return its public view.
     */
    public static SigningKeyResponse from(final SigningKey key) {
        return new SigningKeyResponse(key.kid(), key.alg(), key.status().name(), key.createdAt(),
                key.activatedAt(), key.retiredAt(), key.publicJwk());
    }
}
