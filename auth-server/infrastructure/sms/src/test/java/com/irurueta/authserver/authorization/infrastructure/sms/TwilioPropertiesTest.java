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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Unit tests of {@link TwilioProperties}. */
class TwilioPropertiesTest {

    /** The auth token never appears in the string form. */
    @Test
    void toString_whenCalled_doesNotRevealAuthToken() {
        final var text = new TwilioProperties("test-sid", "test-token", "+15005550006", null).toString();
        assertFalse(text.contains("test-token"));
        assertTrue(text.contains("test-sid"));
    }
}
