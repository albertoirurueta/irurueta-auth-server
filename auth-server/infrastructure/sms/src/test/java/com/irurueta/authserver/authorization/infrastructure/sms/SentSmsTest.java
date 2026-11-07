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

package com.irurueta.authserver.authorization.infrastructure.sms;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link SentSms}. */
class SentSmsTest {

    /** Test fixture. */
    private static final PhoneNumber TO = new PhoneNumber("+34600111222");

    /** A missing component is refused. */
    @Test
    void constructor_whenTextIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SentSms(TO, null, Instant.EPOCH));
    }

    /** The text is not part of the string form. */
    @Test
    void toString_whenCalled_doesNotContainText() {
        final var text = new SentSms(TO, "secret-text", Instant.EPOCH).toString();
        assertFalse(text.contains("secret-text"));
        assertTrue(text.contains("+34600111222"));
    }
}
