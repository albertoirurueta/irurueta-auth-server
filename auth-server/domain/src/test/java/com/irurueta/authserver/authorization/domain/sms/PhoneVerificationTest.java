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
package com.irurueta.authserver.authorization.domain.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PhoneVerification}.
 */
class PhoneVerificationTest {

    /** User identifier used by the tests. */
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    /** Number used by the tests. */
    private static final PhoneNumber PHONE = new PhoneNumber("+34600123456");

    /** Attempts used by the tests. */
    private static final int ATTEMPTS = 3;

    /** Expiry used by the tests. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-01T00:10:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var verification = new PhoneVerification(USER_ID, PHONE, "hash", ATTEMPTS, EXPIRES_AT);

        assertEquals(USER_ID, verification.userId());
        assertEquals(PHONE, verification.phone());
        assertEquals("hash", verification.codeHash());
        assertEquals(ATTEMPTS, verification.attempts());
        assertEquals(EXPIRES_AT, verification.expiresAt());
    }

    /**
     * Verifies that a missing user is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new PhoneVerification(null, PHONE, "hash", 0, EXPIRES_AT));
    }

    /**
     * Verifies that a missing number is rejected.
     */
    @Test
    void constructor_whenPhoneIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new PhoneVerification(USER_ID, null, "hash", 0, EXPIRES_AT));
    }

    /**
     * Verifies that a blank hash is rejected.
     */
    @Test
    void constructor_whenHashIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new PhoneVerification(USER_ID, PHONE, " ", 0, EXPIRES_AT));
    }

    /**
     * Verifies that negative attempts are rejected.
     */
    @Test
    void constructor_whenAttemptsAreNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new PhoneVerification(USER_ID, PHONE, "hash", -1, EXPIRES_AT));
    }

    /**
     * Verifies that a missing expiry is rejected.
     */
    @Test
    void constructor_whenExpiresAtIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new PhoneVerification(USER_ID, PHONE, "hash", 0, null));
    }

    /**
     * Verifies the expiry boundary.
     */
    @Test
    void isExpiredAt_whenBeforeAtAndAfterExpiry_reflectsBoundary() {
        final var verification = new PhoneVerification(USER_ID, PHONE, "hash", 0, EXPIRES_AT);

        assertFalse(verification.isExpiredAt(EXPIRES_AT.minusSeconds(1)));
        assertTrue(verification.isExpiredAt(EXPIRES_AT));
        assertTrue(verification.isExpiredAt(EXPIRES_AT.plusSeconds(1)));
    }
}
