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

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SmsRefusedException} and its subclasses and of {@link InvalidPhoneNumberException}.
 */
class SmsRefusedExceptionTest {

    /**
     * Verifies that the refusals share the base type and carry fixed messages.
     */
    @Test
    void constructor_whenSubclassesAreCreated_areRefusalsWithFixedMessages() {
        assertInstanceOf(SmsRefusedException.class, new SmsCountryNotAllowedException());
        assertInstanceOf(SmsRefusedException.class, new SmsBudgetExceededException());
        assertEquals("custom", new SmsRefusedException("custom").getMessage());
        assertEquals("The phone number is not valid", new InvalidPhoneNumberException().getMessage());
    }
}
