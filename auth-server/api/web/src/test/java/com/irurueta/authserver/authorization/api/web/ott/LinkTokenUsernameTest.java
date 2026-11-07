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

/** Unit tests of {@link LinkTokenUsername}. */
class LinkTokenUsernameTest {

    /** Characters beyond the column. */
    private static final int EXTRA = 5;

    /** Control characters and surrounding blanks are removed. */
    @Test
    void clean_whenTheIdentifierHasControlCharactersAndBlanks_removesThem() {
        assertEquals("alice", LinkTokenUsername.clean("  \u001fal\u0000ice\n "));
    }

    /** A missing identifier is empty. */
    @Test
    void clean_whenNull_isEmpty() {
        assertEquals("", LinkTokenUsername.clean(null));
    }

    /** A too long identifier is cut to what the column holds. */
    @Test
    void clean_whenTooLong_isCutToTheColumnSize() {
        assertEquals(LinkTokenUsername.MAX_LENGTH,
                LinkTokenUsername.clean("a".repeat(LinkTokenUsername.MAX_LENGTH + EXTRA)).length());
    }

    /** A sign-in link is stored under the plain identifier. */
    @Test
    void forLink_whenNotSecondFactor_isThePlainIdentifier() {
        assertEquals("alice", LinkTokenUsername.forLink("alice", false));
    }

    /** A second-factor link carries the marker, and is told apart and unmarked again. */
    @Test
    void forLink_whenSecondFactor_carriesTheMarker() {
        final var stored = LinkTokenUsername.forLink("alice", true);

        assertTrue(LinkTokenUsername.isSecondFactor(stored));
        assertEquals("alice", LinkTokenUsername.identifierOf(stored));
    }

    /** The marker never pushes the stored value past the column. */
    @Test
    void forLink_whenIdentifierTakesTheWholeColumn_isCutToTheColumnSize() {
        final var stored = LinkTokenUsername.forLink("a".repeat(LinkTokenUsername.MAX_LENGTH), true);

        assertEquals(LinkTokenUsername.MAX_LENGTH, stored.length());
    }

    /** A plain or empty stored value is not a second-factor one. */
    @Test
    void isSecondFactor_whenPlainOrEmpty_isFalse() {
        assertFalse(LinkTokenUsername.isSecondFactor("alice"));
        assertFalse(LinkTokenUsername.isSecondFactor(""));
        assertFalse(LinkTokenUsername.isSecondFactor(null));
        assertEquals("alice", LinkTokenUsername.identifierOf("alice"));
    }
}
