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
package com.irurueta.authserver.authorization.application.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SmsRequested}.
 */
class SmsRequestedTest {

    /** Destination used by the tests. */
    private static final PhoneNumber TO = new PhoneNumber("+34600000000");

    /** Text used by the tests. */
    private static final String TEXT = "Your verification code is 123456.";

    /**
     * Verifies that a valid event keeps its values.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var event = new SmsRequested(TO, TEXT);

        assertEquals(TO, event.to());
        assertEquals(TEXT, event.text());
    }

    /**
     * Verifies that missing or blank values are rejected.
     */
    @Test
    void constructor_whenAValueIsMissing_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsRequested(null, TEXT));
        assertThrows(IllegalArgumentException.class, () -> new SmsRequested(TO, null));
        assertThrows(IllegalArgumentException.class, () -> new SmsRequested(TO, " "));
    }

    /**
     * Verifies that the description carries neither the number nor the text.
     */
    @Test
    void toString_whenCalled_hidesTheNumberAndTheText() {
        final var text = new SmsRequested(TO, TEXT).toString();

        assertFalse(text.contains(TO.e164()));
        assertFalse(text.contains("123456"));
    }
}
