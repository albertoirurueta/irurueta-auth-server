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
package com.irurueta.authserver.authorization.domain.ott;

import java.time.Duration;

/**
 * The rules of one-time tokens: how long each kind lives, how long a code is and how many wrong submissions are
 * tolerated. It is pure: it knows nothing about storage or delivery.
 */
public final class OttPolicy {

    /** Length of the numeric code, in digits. */
    private final int codeLength;

    /** Lifetime of a numeric code. */
    private final Duration codeTtl;

    /** Lifetime of a magic link. */
    private final Duration linkTtl;

    /** Wrong submissions tolerated before a code is rejected for good. */
    private final int maxAttempts;

    /**
     * Creates the policy.
     *
     * @param codeLength  length of the numeric code, in digits; positive.
     * @param codeTtl     lifetime of a numeric code; positive.
     * @param linkTtl     lifetime of a magic link; positive.
     * @param maxAttempts wrong submissions tolerated per code; positive.
     * @throws IllegalArgumentException if a number is not positive or a lifetime is missing, zero or negative.
     */
    public OttPolicy(final int codeLength, final Duration codeTtl, final Duration linkTtl, final int maxAttempts) {
        if (codeLength <= 0) {
            throw new IllegalArgumentException("codeLength must be positive");
        }
        requirePositive(codeTtl, "codeTtl");
        requirePositive(linkTtl, "linkTtl");
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("maxAttempts must be positive");
        }
        this.codeLength = codeLength;
        this.codeTtl = codeTtl;
        this.linkTtl = linkTtl;
        this.maxAttempts = maxAttempts;
    }

    /**
     * Gets the length of the numeric code.
     *
     * @return number of digits.
     */
    public int codeLength() {
        return codeLength;
    }

    /**
     * Gets the lifetime of a token of a kind.
     *
     * @param kind kind of token.
     * @return the lifetime.
     */
    public Duration ttl(final OttKind kind) {
        return switch (kind) {
            case CODE -> codeTtl;
            case LINK -> linkTtl;
        };
    }

    /**
     * Gets the wrong submissions tolerated per code.
     *
     * @return the limit.
     */
    public int maxAttempts() {
        return maxAttempts;
    }

    /**
     * Tells whether a code has used up its attempts.
     *
     * @param attempts wrong submissions so far.
     * @return {@code true} when {@code attempts} reaches the limit.
     */
    public boolean isExhausted(final int attempts) {
        return attempts >= maxAttempts;
    }

    /**
     * Rejects a missing, zero or negative duration.
     *
     * @param value value to check.
     * @param name  name of the value, for the message.
     */
    private static void requirePositive(final Duration value, final String name) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
