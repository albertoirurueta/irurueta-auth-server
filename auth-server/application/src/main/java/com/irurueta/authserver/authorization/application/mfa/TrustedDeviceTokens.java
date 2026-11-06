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

package com.irurueta.authserver.authorization.application.mfa;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

/**
 * Creates the random tokens that identify a trusted device and hashes them, so only the SHA-256 hash is ever stored.
 */
@Component
public class TrustedDeviceTokens {

    /** Size of a token in bytes (256 bits). */
    public static final int TOKEN_BYTES = 32;

    /** Name of the hash algorithm. */
    private static final String HASH_ALGORITHM = "SHA-256";

    /** Source of randomness. */
    private final SecureRandom random = new SecureRandom();

    /**
     * Creates a new random token.
     *
     * @return the URL-safe token, to be handed to the browser once.
     */
    public String newToken() {
        final var bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Hashes a token.
     *
     * @param token the raw token.
     * @return the lowercase hexadecimal SHA-256 hash.
     */
    public String hash(final String token) {
        try {
            final var digest = MessageDigest.getInstance(HASH_ALGORITHM);
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(HASH_ALGORITHM + " is not available", e);
        }
    }
}
