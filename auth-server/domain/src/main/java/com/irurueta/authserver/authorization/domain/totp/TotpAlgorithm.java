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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Locale;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// tag::totp-algorithm[]
/**
 * The time-based one-time password algorithm of RFC 6238 over HMAC-SHA1, with the parameters every authenticator
 * application supports: 30 second steps and 6 digits. It is pure and holds no state.
 */
public class TotpAlgorithm {

    /** Length of a time step, in seconds. */
    public static final long PERIOD_SECONDS = 30L;

    /** Number of digits of a code. */
    public static final int DIGITS = 6;

    /** Number of steps accepted on each side of the current one, to tolerate clock drift. */
    public static final int WINDOW = 1;

    /** Name of the algorithm as written in an {@code otpauth} URI. */
    public static final String ALGORITHM_NAME = "SHA1";

    /** Name of the JCA MAC algorithm. */
    private static final String MAC_ALGORITHM = "HmacSHA1";

    /** Modulus that keeps the last {@link #DIGITS} decimal digits. */
    private static final int MODULUS = 1_000_000;

    /** Mask of the low nibble of the last hash byte, which gives the truncation offset. */
    private static final int OFFSET_MASK = 0x0f;

    /** Mask that clears the sign bit of the truncated word. */
    private static final int SIGN_MASK = 0x7fffffff;

    /** Number of bytes of the truncated word. */
    private static final int TRUNCATED_BYTES = 4;

    /**
     * Computes the code of a time step.
     *
     * @param secret the shared secret.
     * @param step   the time step, that is the Unix time divided by {@link #PERIOD_SECONDS}.
     * @return the code, always {@link #DIGITS} digits long, left padded with zeros.
     * @throws IllegalArgumentException if the secret is empty.
     * @throws IllegalStateException    if the platform has no HMAC-SHA1.
     */
    public String generate(final byte[] secret, final long step) {
        try {
            final var mac = Mac.getInstance(MAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, MAC_ALGORITHM));
            final var hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(step).array());
            final var offset = hash[hash.length - 1] & OFFSET_MASK;
            final var truncated = ByteBuffer.wrap(hash, offset, TRUNCATED_BYTES).getInt() & SIGN_MASK;
            return String.format(Locale.ROOT, "%0" + DIGITS + "d", truncated % MODULUS);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA1 is not available", e);
        }
    }

    /**
     * Computes the time step that contains an instant.
     *
     * @param instant the instant.
     * @return the step.
     */
    public long stepAt(final Instant instant) {
        return Math.floorDiv(instant.getEpochSecond(), PERIOD_SECONDS);
    }

    /**
     * Finds the time step a presented code corresponds to, accepting {@link #WINDOW} steps on each side of the current
     * one and rejecting any step that is not newer than the last one used, so that a code cannot be replayed.
     *
     * @param secret       the shared secret.
     * @param code         the code presented by the user.
     * @param now          current instant.
     * @param lastUsedStep the step of the last accepted code, or {@link TotpCredential#NEVER_USED}.
     * @return the matching step, or an empty value when the code is wrong, outside the window or already used.
     */
    public OptionalLong matchingStep(
            final byte[] secret, final String code, final Instant now, final long lastUsedStep) {
        if (code == null || code.length() != DIGITS) {
            return OptionalLong.empty();
        }
        final var presented = code.getBytes(StandardCharsets.US_ASCII);
        final var current = stepAt(now);
        var match = OptionalLong.empty();
        for (var step = current - WINDOW; step <= current + WINDOW; step++) {
            final var expected = generate(secret, step).getBytes(StandardCharsets.US_ASCII);
            // every step is compared, in constant time, so the response time does not reveal which one matched
            final var equal = MessageDigest.isEqual(expected, presented);
            if (equal && step > lastUsedStep && match.isEmpty()) {
                match = OptionalLong.of(step);
            }
        }
        return match;
    }

    /**
     * Tells whether a code is valid, with the window and replay rules of {@link #matchingStep}.
     *
     * @param secret       the shared secret.
     * @param code         the code presented by the user.
     * @param now          current instant.
     * @param lastUsedStep the step of the last accepted code, or {@link TotpCredential#NEVER_USED}.
     * @return {@code true} when the code is accepted.
     */
    public boolean matches(final byte[] secret, final String code, final Instant now, final long lastUsedStep) {
        return matchingStep(secret, code, now, lastUsedStep).isPresent();
    }
}
// end::totp-algorithm[]
