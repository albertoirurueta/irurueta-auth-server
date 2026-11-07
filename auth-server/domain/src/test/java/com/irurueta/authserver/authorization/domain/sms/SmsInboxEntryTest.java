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

import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link SmsInboxEntry}. */
class SmsInboxEntryTest {

    /** Test fixture. */
    private static final PhoneNumber TO = new PhoneNumber("+34600111222");

    /** Test fixture. */
    private static final String TEXT = "Your code is 123456";

    /** A complete entry keeps its components. */
    @Test
    void constructor_whenComplete_keepsComponents() {
        final var entry = new SmsInboxEntry(TO, TEXT, Instant.EPOCH);

        assertEquals(TO, entry.to());
        assertEquals(TEXT, entry.text());
        assertEquals(Instant.EPOCH, entry.sentAt());
    }

    /** A missing component is refused. */
    @Test
    void constructor_whenAComponentIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsInboxEntry(null, TEXT, Instant.EPOCH));
        assertThrows(IllegalArgumentException.class, () -> new SmsInboxEntry(TO, null, Instant.EPOCH));
        assertThrows(IllegalArgumentException.class, () -> new SmsInboxEntry(TO, TEXT, null));
    }

    /** The description leaves the text, which carries a code, out. */
    @Test
    void toString_whenCalled_omitsTheText() {
        assertFalse(new SmsInboxEntry(TO, TEXT, Instant.EPOCH).toString().contains("123456"));
    }
}
