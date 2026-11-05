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

package com.irurueta.authserver.authorization.infrastructure.keys;

import com.irurueta.authserver.authorization.domain.account.TokenGenerator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * {@link TokenGenerator} that creates tokens from a {@link SecureRandom} and hashes them with SHA-256. The tokens
 * are random with 256 bits of entropy, so a fast deterministic hash is enough to store them.
 */
@Component
public class SecureTokenGenerator implements TokenGenerator {

    /** Number of random bytes of a token. */
    static final int TOKEN_BYTES = 32;

    /** Name of the hash algorithm. */
    private static final String ALGORITHM = "SHA-256";

    /** Source of randomness. */
    private final SecureRandom random = new SecureRandom();

    @Override
    public String generate() {
        final var bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String hash(final String token) {
        return digest(ALGORITHM, token);
    }

    /**
     * Hashes a token with a message digest algorithm.
     *
     * @param algorithm name of the algorithm.
     * @param token     the token value.
     * @return the URL-safe, unpadded Base64 digest.
     * @throws IllegalStateException if the algorithm is not available.
     */
    static String digest(final String algorithm, final String token) {
        try {
            final var digest = MessageDigest.getInstance(algorithm).digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (final NoSuchAlgorithmException e) {
            // every Java platform must provide SHA-256, so this only happens for another algorithm name
            throw new IllegalStateException(algorithm + " is not available", e);
        }
    }
}
