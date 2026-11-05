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

package com.irurueta.authserver.authorization.infrastructure.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link KeyEncryptionProperties}.
 */
class KeyEncryptionPropertiesTest {

    /**
     * Verifies that the components are kept.
     */
    @Test
    void constructor_whenValuesAreSet_keepsThem() {
        final var first = UUID.randomUUID().toString();
        final var second = UUID.randomUUID().toString();

        final var properties = new KeyEncryptionProperties(first, second);

        assertEquals(first, properties.password());
        assertEquals(second, properties.salt());
    }

    /**
     * Verifies that a blank or missing passphrase is rejected.
     */
    @Test
    void constructor_whenPassphraseIsBlankOrNull_throwsIllegalArgumentException() {
        final var salt = UUID.randomUUID().toString();

        assertThrows(IllegalArgumentException.class, () -> new KeyEncryptionProperties(" ", salt));
        assertThrows(IllegalArgumentException.class, () -> new KeyEncryptionProperties(null, salt));
    }

    /**
     * Verifies that a blank or missing salt is rejected.
     */
    @Test
    void constructor_whenSaltIsBlankOrNull_throwsIllegalArgumentException() {
        final var passphrase = UUID.randomUUID().toString();

        assertThrows(IllegalArgumentException.class, () -> new KeyEncryptionProperties(passphrase, ""));
        assertThrows(IllegalArgumentException.class, () -> new KeyEncryptionProperties(passphrase, null));
    }

    /**
     * Verifies that the text form does not reveal the values.
     */
    @Test
    void toString_whenCalled_doesNotRevealValues() {
        final var passphrase = UUID.randomUUID().toString();

        final var text = new KeyEncryptionProperties(passphrase, UUID.randomUUID().toString()).toString();

        assertFalse(text.contains(passphrase));
    }
}
