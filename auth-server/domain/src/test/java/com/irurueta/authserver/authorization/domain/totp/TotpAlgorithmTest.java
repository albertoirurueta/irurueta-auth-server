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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TotpAlgorithm}.
 */
class TotpAlgorithmTest {

    /** Shared secret of the RFC 6238 test vectors for HMAC-SHA1. */
    private static final byte[] SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    /** Unix time of the codes used by the window and replay tests; it falls in step 1. */
    private static final long BASE_TIME = 59L;

    /** Step that contains {@link #BASE_TIME}. */
    private static final long BASE_STEP = 1L;

    /** The 8-digit codes of RFC 6238 Appendix B for SHA-1, by Unix time. */
    private static final Map<Long, String> RFC_VECTORS = Map.of(
            59L, "94287082",
            1_111_111_109L, "07081804",
            1_111_111_111L, "14050471",
            1_234_567_890L, "89005924",
            2_000_000_000L, "69279037",
            20_000_000_000L, "65353130");

    /** Subject under test. */
    private final TotpAlgorithm algorithm = new TotpAlgorithm();

    /**
     * Verifies that the codes match the RFC 6238 vectors, whose 8-digit values truncate to the 6-digit codes.
     */
    @Test
    void generate_whenRfcVector_matchesTruncatedExpectedCode() {
        for (final var vector : RFC_VECTORS.entrySet()) {
            final var step = algorithm.stepAt(Instant.ofEpochSecond(vector.getKey()));

            final var code = algorithm.generate(SECRET, step);

            assertEquals(vector.getValue().substring(vector.getValue().length() - TotpAlgorithm.DIGITS), code);
        }
    }

    /**
     * Verifies that the step is the Unix time divided by the period.
     */
    @Test
    void stepAt_whenInstantIsGiven_returnsFlooredStep() {
        assertEquals(BASE_STEP, algorithm.stepAt(Instant.ofEpochSecond(BASE_TIME)));
        assertEquals(BASE_STEP + 1, algorithm.stepAt(Instant.ofEpochSecond(BASE_TIME + 1)));
    }

    /**
     * Verifies that the current code is accepted and its step reported.
     */
    @Test
    void matchingStep_whenCodeIsCurrent_returnsItsStep() {
        final var code = algorithm.generate(SECRET, BASE_STEP);

        assertEquals(OptionalLong.of(BASE_STEP),
                algorithm.matchingStep(SECRET, code, Instant.ofEpochSecond(BASE_TIME), TotpCredential.NEVER_USED));
    }

    /**
     * Verifies that the code of the previous step is accepted.
     */
    @Test
    void matches_whenCodeIsOneStepOld_returnsTrue() {
        final var code = algorithm.generate(SECRET, BASE_STEP - 1);

        assertTrue(algorithm.matches(SECRET, code, Instant.ofEpochSecond(BASE_TIME), TotpCredential.NEVER_USED));
    }

    /**
     * Verifies that the code of the next step is accepted.
     */
    @Test
    void matches_whenCodeIsOneStepAhead_returnsTrue() {
        final var code = algorithm.generate(SECRET, BASE_STEP + 1);

        assertTrue(algorithm.matches(SECRET, code, Instant.ofEpochSecond(BASE_TIME), TotpCredential.NEVER_USED));
    }

    /**
     * Verifies that a code two steps old is rejected.
     */
    @Test
    void matches_whenCodeIsTwoStepsOld_returnsFalse() {
        final var now = Instant.ofEpochSecond(BASE_TIME + 2 * TotpAlgorithm.PERIOD_SECONDS);
        final var code = algorithm.generate(SECRET, algorithm.stepAt(now) - 2);

        assertFalse(algorithm.matches(SECRET, code, now, TotpCredential.NEVER_USED));
    }

    /**
     * Verifies that a code two steps ahead is rejected.
     */
    @Test
    void matches_whenCodeIsTwoStepsAhead_returnsFalse() {
        final var code = algorithm.generate(SECRET, BASE_STEP + 2);

        assertFalse(algorithm.matches(SECRET, code, Instant.ofEpochSecond(BASE_TIME), TotpCredential.NEVER_USED));
    }

    /**
     * Verifies that the code of an already used step is rejected, which is replay protection.
     */
    @Test
    void matches_whenStepWasAlreadyUsed_returnsFalse() {
        final var code = algorithm.generate(SECRET, BASE_STEP);

        assertFalse(algorithm.matches(SECRET, code, Instant.ofEpochSecond(BASE_TIME), BASE_STEP));
    }

    /**
     * Verifies that a code of an older step than the last used one is rejected too.
     */
    @Test
    void matches_whenStepIsOlderThanLastUsed_returnsFalse() {
        final var code = algorithm.generate(SECRET, BASE_STEP - 1);

        assertFalse(algorithm.matches(SECRET, code, Instant.ofEpochSecond(BASE_TIME), BASE_STEP));
    }

    /**
     * Verifies that a newer step than the last used one is accepted.
     */
    @Test
    void matches_whenStepIsNewerThanLastUsed_returnsTrue() {
        final var code = algorithm.generate(SECRET, BASE_STEP + 1);

        assertTrue(algorithm.matches(SECRET, code, Instant.ofEpochSecond(BASE_TIME), BASE_STEP));
    }

    /**
     * Verifies that a missing code is rejected.
     */
    @Test
    void matches_whenCodeIsNull_returnsFalse() {
        assertFalse(algorithm.matches(SECRET, null, Instant.ofEpochSecond(BASE_TIME), TotpCredential.NEVER_USED));
    }

    /**
     * Verifies that a code of the wrong length is rejected.
     */
    @Test
    void matches_whenCodeHasWrongLength_returnsFalse() {
        assertFalse(algorithm.matches(SECRET, "12345", Instant.ofEpochSecond(BASE_TIME), TotpCredential.NEVER_USED));
    }

    /**
     * Verifies that a wrong code of the right length is rejected.
     */
    @Test
    void matches_whenCodeIsWrong_returnsFalse() {
        final var wrong = algorithm.generate(SECRET, BASE_STEP).equals("000000") ? "000001" : "000000";

        assertFalse(algorithm.matches(SECRET, wrong, Instant.ofEpochSecond(BASE_TIME), TotpCredential.NEVER_USED));
    }
}
