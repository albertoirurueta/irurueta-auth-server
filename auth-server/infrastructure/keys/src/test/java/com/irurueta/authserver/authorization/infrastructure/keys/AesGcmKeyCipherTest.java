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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link AesGcmKeyCipher}.
 */
class AesGcmKeyCipherTest {

    /** Properties shared by the cipher under test. */
    private final KeyEncryptionProperties properties = KeyTestSupport.randomProperties();

    /** Cipher under test. */
    private final AesGcmKeyCipher cipher = new AesGcmKeyCipher(properties);

    /**
     * Verifies that a decrypted text equals the original.
     */
    @Test
    void decrypt_whenTextWasEncrypted_returnsOriginal() {
        final var plain = UUID.randomUUID().toString();

        final var encrypted = cipher.encrypt(plain);

        assertNotEquals(plain, encrypted);
        assertEquals(plain, cipher.decrypt(encrypted));
    }

    /**
     * Verifies that two encryptions of one text differ, because the initialisation vector is random.
     */
    @Test
    void encrypt_whenCalledTwiceWithSameText_givesDifferentResults() {
        final var plain = UUID.randomUUID().toString();

        assertNotEquals(cipher.encrypt(plain), cipher.encrypt(plain));
    }

    /**
     * Verifies that another passphrase cannot decrypt.
     */
    @Test
    void decrypt_whenCipherUsesOtherPassphrase_throwsIllegalStateException() {
        final var encrypted = cipher.encrypt(UUID.randomUUID().toString());
        final var other = new AesGcmKeyCipher(
                new KeyEncryptionProperties(UUID.randomUUID().toString(), properties.salt()));

        assertThrows(IllegalStateException.class, () -> other.decrypt(encrypted));
    }

    /**
     * Verifies that an altered text is rejected.
     */
    @Test
    void decrypt_whenTextIsAltered_throwsIllegalStateException() {
        final var encrypted = cipher.encrypt(UUID.randomUUID().toString());
        final var middle = encrypted.length() / 2;
        final var replacement = encrypted.charAt(middle) == 'A' ? 'B' : 'A';
        final var altered = encrypted.substring(0, middle) + replacement + encrypted.substring(middle + 1);

        assertThrows(IllegalStateException.class, () -> cipher.decrypt(altered));
    }

    /**
     * Verifies that text that is not Base64 is rejected.
     */
    @Test
    void decrypt_whenTextIsNotBase64_throwsIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> cipher.decrypt("not base64!"));
    }
}
