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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** Unit tests of {@link SmsOutboxProperties}. */
class SmsOutboxPropertiesTest {

    /** Test fixture. */
    private static final int CUSTOM = 7;

    /** Zero selects the default. */
    @Test
    void constructor_whenCapacityIsZero_usesDefault() {
        assertEquals(SmsOutboxProperties.DEFAULT_CAPACITY, new SmsOutboxProperties(0).capacity());
    }

    /** A positive value is kept. */
    @Test
    void constructor_whenCapacityIsPositive_keepsIt() {
        assertEquals(CUSTOM, new SmsOutboxProperties(CUSTOM).capacity());
    }
}
