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

package com.irurueta.authserver.serviceclient.device;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TokenResponse}.
 */
class TokenResponseTest {

    /** The expires in. */
    private static final long EXPIRES_IN = 300L;

    /**
     * Neither token appears in the description.
     */
    @Test
    void toString_whenCalled_hidesBothTokens() {
        final var text = new TokenResponse("secret-at", "secret-rt", "Bearer", EXPIRES_IN, "profile").toString();

        assertFalse(text.contains("secret-at"));
        assertFalse(text.contains("secret-rt"));
        assertTrue(text.contains("Bearer"));
    }
}
