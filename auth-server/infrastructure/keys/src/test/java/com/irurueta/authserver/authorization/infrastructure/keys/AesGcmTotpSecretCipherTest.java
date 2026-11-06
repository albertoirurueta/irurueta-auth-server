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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.encrypt.Encryptors;

/**
 * Unit tests of {@link AesGcmTotpSecretCipher}, with a secret generated at run time.
 */
class AesGcmTotpSecretCipherTest {

    /** Properties shared by the cipher under test. */
    private final KeyEncryptionProperties properties = KeyTestSupport.randomProperties();

    /** Cipher under test. */
    private final AesGcmTotpSecretCipher cipher =
            new AesGcmTotpSecretCipher(properties, new PurposeKeyDerivation(properties));

    /**
     * Verifies that a decrypted secret equals the original and the encrypted form differs.
     */
    @Test
    void decrypt_whenSecretWasEncrypted_returnsOriginal() {
        final var secret = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);

        final var encrypted = cipher.encrypt(secret);

        assertFalse(Arrays.equals(secret, encrypted));
        assertArrayEquals(secret, cipher.decrypt(encrypted));
    }

    /**
     * Verifies that two encryptions of one secret differ, because the initialisation vector is random.
     */
    @Test
    void encrypt_whenCalledTwiceWithSameSecret_givesDifferentResults() {
        final var secret = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);

        assertFalse(Arrays.equals(cipher.encrypt(secret), cipher.encrypt(secret)));
    }

    /**
     * Verifies that another passphrase cannot decrypt.
     */
    @Test
    void decrypt_whenCipherUsesOtherPassphrase_throwsIllegalStateException() {
        final var encrypted = cipher.encrypt(new byte[] {1, 2, 3});
        final var otherProperties = new KeyEncryptionProperties(UUID.randomUUID().toString(), properties.salt());
        final var other = new AesGcmTotpSecretCipher(otherProperties, new PurposeKeyDerivation(otherProperties));

        assertThrows(IllegalStateException.class, () -> other.decrypt(encrypted));
    }

    /**
     * Verifies that an altered value is rejected.
     */
    @Test
    void decrypt_whenValueIsAltered_throwsIllegalStateException() {
        final var encrypted = cipher.encrypt(new byte[] {1, 2, 3});
        encrypted[encrypted.length - 1] ^= 1;

        assertThrows(IllegalStateException.class, () -> cipher.decrypt(encrypted));
    }

    /**
     * Verifies that the key of the signing keys, derived from the same passphrase and the configured salt itself,
     * cannot decrypt a TOTP secret: the two purposes never share a key.
     */
    @Test
    void decrypt_whenValueWasEncryptedWithSigningKeyKey_throwsIllegalStateException() {
        final var signingKeyEncryptor = Encryptors.stronger(properties.password(), properties.salt());
        final var encrypted = signingKeyEncryptor.encrypt(new byte[] {1, 2, 3});

        assertThrows(IllegalStateException.class, () -> cipher.decrypt(encrypted));
    }

    /**
     * Verifies that a value too short to hold an initialisation vector is rejected.
     */
    @Test
    void decrypt_whenValueIsTooShort_throwsIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> cipher.decrypt(new byte[] {1}));
    }
}
