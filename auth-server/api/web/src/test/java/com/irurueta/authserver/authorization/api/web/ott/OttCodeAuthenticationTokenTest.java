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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Unit tests of {@link OttCodeAuthenticationToken}. */
class OttCodeAuthenticationTokenTest {

    /** The request exposes its parts and is never authenticated. */
    @Test
    void constructor_whenCreated_exposesItsPartsAndIsNotAuthenticated() {
        final var token = new OttCodeAuthenticationToken("alice", "123456", "binding");

        assertEquals("alice", token.getPrincipal());
        assertEquals("123456", token.getCredentials());
        assertEquals("binding", token.bindingId());
        assertFalse(token.isAuthenticated());
    }

    /** Digits are a code; a UUID, letters, blanks and long numbers are not. */
    @Test
    void isCode_whenGivenDifferentValues_onlyShortDigitStringsAreCodes() {
        assertTrue(OttCodeAuthenticationToken.isCode("123456"));
        assertTrue(OttCodeAuthenticationToken.isCode("0"));
        assertFalse(OttCodeAuthenticationToken.isCode("123e4567-e89b-12d3-a456-426614174000"));
        assertFalse(OttCodeAuthenticationToken.isCode("12 34"));
        assertFalse(OttCodeAuthenticationToken.isCode("1234567890123"));
        assertFalse(OttCodeAuthenticationToken.isCode(""));
        assertFalse(OttCodeAuthenticationToken.isCode(null));
    }

    /** Equal parts are equal requests. */
    @Test
    void equalsAndHashCode_whenPartsMatch_areEqual() {
        final var first = new OttCodeAuthenticationToken("alice", "123456", "binding");
        final var second = new OttCodeAuthenticationToken("alice", "123456", "binding");

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }
}
