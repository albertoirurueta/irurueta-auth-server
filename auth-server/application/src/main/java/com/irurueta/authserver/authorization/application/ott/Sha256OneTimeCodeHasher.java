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

package com.irurueta.authserver.authorization.application.ott;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Hashes one-time codes with SHA-256 (lower-case hex) and compares them in constant time.
 *
 * <p>A plain hash of a six-digit code can be brute-forced in an instant if the table leaks. That is acceptable here
 * only because a code is single use, lives for minutes and is burnt after a few wrong attempts, so a leaked row is
 * useless by the time anyone could read it. Never use this hasher for a long-lived secret.
 */
public class Sha256OneTimeCodeHasher implements OneTimeCodeHasher {

    /** Name of the digest algorithm. */
    private static final String ALGORITHM = "SHA-256";

    /**
     * Hashes a code.
     *
     * @param code the clear-text code.
     * @return the hash as lower-case hex.
     */
    @Override
    public String hash(final String code) {
        return HexFormat.of().formatHex(digest(code));
    }

    /**
     * Tells whether a code produces a hash, in constant time.
     *
     * @param code the clear-text code, possibly {@code null}.
     * @param hash the stored hash, possibly {@code null}.
     * @return {@code true} when they correspond.
     */
    @Override
    public boolean matches(final String code, final String hash) {
        if (code == null || hash == null) {
            return false;
        }
        return MessageDigest.isEqual(hash(code).getBytes(StandardCharsets.UTF_8),
                hash.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes the SHA-256 digest of a text.
     *
     * @param text the text.
     * @return the digest bytes.
     */
    private static byte[] digest(final String text) {
        try {
            return MessageDigest.getInstance(ALGORITHM).digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (final NoSuchAlgorithmException e) {
            // every Java platform must provide SHA-256
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
