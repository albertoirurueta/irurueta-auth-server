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

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SmsMessage}.
 */
class SmsMessageTest {

    /** Recipient used by the tests. */
    private static final PhoneNumber TO = new PhoneNumber("+34600123456");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var message = new SmsMessage(TO, "hello");

        assertEquals(TO, message.to());
        assertEquals("hello", message.body());
    }

    /**
     * Verifies that a missing recipient is rejected.
     */
    @Test
    void constructor_whenRecipientIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsMessage(null, "hello"));
    }

    /**
     * Verifies that a blank body is rejected.
     */
    @Test
    void constructor_whenBodyIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsMessage(TO, " "));
    }
}
