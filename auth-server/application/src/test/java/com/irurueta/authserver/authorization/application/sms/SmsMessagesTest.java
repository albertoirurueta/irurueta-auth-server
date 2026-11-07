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

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SmsMessages}.
 */
class SmsMessagesTest {

    /** Validity of the code. */
    private static final Duration TEN_MINUTES = Duration.ofMinutes(10);

    /**
     * Verifies the text of a verification message.
     */
    @Test
    void verificationCode_whenCalled_includesCodeAndMinutes() {
        assertEquals("Your verification code is 123456. It is valid for 10 minutes.",
                SmsMessages.verificationCode("123456", TEN_MINUTES));
    }

    /**
     * Verifies that a validity shorter than a minute is announced as one minute.
     */
    @Test
    void verificationCode_whenValidityIsUnderAMinute_announcesOneMinute() {
        assertEquals("Your verification code is 000000. It is valid for 1 minutes.",
                SmsMessages.verificationCode("000000", Duration.ofSeconds(1)));
    }
}
