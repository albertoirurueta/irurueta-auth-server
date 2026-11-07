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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link UserPhone}.
 */
class UserPhoneTest {

    /** User identifier used by the tests. */
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    /** Number used by the tests. */
    private static final PhoneNumber PHONE = new PhoneNumber("+34600123456");

    /** Verification instant used by the tests. */
    private static final Instant VERIFIED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var phone = new UserPhone(USER_ID, PHONE, VERIFIED_AT);

        assertEquals(USER_ID, phone.userId());
        assertEquals(PHONE, phone.phone());
        assertEquals(VERIFIED_AT, phone.verifiedAt());
    }

    /**
     * Verifies that a missing user is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new UserPhone(null, PHONE, VERIFIED_AT));
    }

    /**
     * Verifies that a missing number is rejected.
     */
    @Test
    void constructor_whenPhoneIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new UserPhone(USER_ID, null, VERIFIED_AT));
    }

    /**
     * Verifies that a missing verification instant is rejected.
     */
    @Test
    void constructor_whenVerifiedAtIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new UserPhone(USER_ID, PHONE, null));
    }
}
