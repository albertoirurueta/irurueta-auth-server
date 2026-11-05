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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.stereotype.Component;

// tag::keys-encryption[]
/**
 * Encrypts and decrypts the private half of signing keys with AES-256-GCM (Spring Security's
 * {@code Encryptors.stronger}). Every encryption uses a fresh random initialisation vector, so encrypting the same
 * text twice gives different results.
 */
@Component
public class AesGcmKeyCipher {

    /** The encryptor derived from the passphrase and the salt. */
    private final BytesEncryptor encryptor;

    /**
     * Derives the encryption key.
     *
     * @param properties passphrase and salt.
     */
    public AesGcmKeyCipher(final KeyEncryptionProperties properties) {
        encryptor = Encryptors.stronger(properties.password(), properties.salt());
    }

    /**
     * Encrypts a text.
     *
     * @param plain the text.
     * @return the encrypted text, Base64 encoded.
     */
    public String encrypt(final String plain) {
        return Base64.getEncoder().encodeToString(encryptor.encrypt(plain.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Decrypts a text produced by {@link #encrypt(String)}.
     *
     * @param encrypted the encrypted text.
     * @return the original text.
     * @throws IllegalStateException if the text was not encrypted with the same passphrase and salt, or was altered.
     */
    public String decrypt(final String encrypted) {
        try {
            return new String(encryptor.decrypt(Base64.getDecoder().decode(encrypted)), StandardCharsets.UTF_8);
        } catch (final RuntimeException e) {
            throw new IllegalStateException("The private key cannot be decrypted", e);
        }
    }
}
// end::keys-encryption[]
