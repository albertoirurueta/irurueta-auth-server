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

package com.irurueta.authserver.authorization.api.web.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link RegisterRequest}.
 */
class RegisterRequestTest {

    /**
     * Checks that the components are kept.
     */
    @Test
    void constructor_whenValuesGiven_keepsThem() {
        final var secret = UUID.randomUUID().toString();
        final var request = new RegisterRequest("alice", "alice@example.com", secret);

        assertEquals("alice", request.username());
        assertEquals("alice@example.com", request.email());
        assertEquals(secret, request.password());
    }

    /**
     * Checks that the password never appears in the text form.
     */
    @Test
    void toString_whenCalled_hidesPassword() {
        final var secret = UUID.randomUUID().toString();
        final var text = new RegisterRequest("alice", "alice@example.com", secret).toString();

        assertFalse(text.contains(secret));
        assertTrue(text.contains("alice@example.com"));
    }
}
