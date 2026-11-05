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

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ResetPasswordRequest}.
 */
class ResetPasswordRequestTest {

    /**
     * Checks that the components are kept.
     */
    @Test
    void constructor_whenValuesGiven_keepsThem() {
        final var token = UUID.randomUUID().toString();
        final var next = UUID.randomUUID().toString();
        final var request = new ResetPasswordRequest(token, next);

        assertEquals(token, request.token());
        assertEquals(next, request.newPassword());
    }

    /**
     * Checks that the token and the password never appear in the text form.
     */
    @Test
    void toString_whenCalled_hidesValues() {
        final var token = UUID.randomUUID().toString();
        final var next = UUID.randomUUID().toString();
        final var text = new ResetPasswordRequest(token, next).toString();

        assertFalse(text.contains(token));
        assertFalse(text.contains(next));
    }
}
