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

import java.security.SecureRandom;

/**
 * Creates 160-bit secrets, the length RFC 4226 recommends for HMAC-SHA1, from a {@link SecureRandom}.
 */
public class SecureRandomSecretGenerator implements SecretGenerator {

    /** Length of a secret in bytes, which is 160 bits. */
    public static final int SECRET_BYTES = 20;

    /** Source of randomness. */
    private final SecureRandom random = new SecureRandom();

    /**
     * Creates an unguessable secret.
     *
     * @return {@link #SECRET_BYTES} random bytes.
     */
    @Override
    public byte[] generate() {
        final var secret = new byte[SECRET_BYTES];
        random.nextBytes(secret);
        return secret;
    }
}
