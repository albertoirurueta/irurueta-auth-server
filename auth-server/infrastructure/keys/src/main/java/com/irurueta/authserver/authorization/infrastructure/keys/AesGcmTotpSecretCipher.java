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

import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.stereotype.Component;

/**
 * {@link TotpSecretCipher} that encrypts TOTP secrets with AES-256 in GCM mode, with a key derived from the same
 * passphrase and salt that protect the signing keys. Each encryption uses a random initialisation vector, which is
 * stored in front of the cipher text.
 */
@Component
public class AesGcmTotpSecretCipher implements TotpSecretCipher {

    /** The encryptor derived from the passphrase and the salt. */
    private final BytesEncryptor encryptor;

    /**
     * Derives the encryption key.
     *
     * @param properties passphrase and salt.
     */
    public AesGcmTotpSecretCipher(final KeyEncryptionProperties properties) {
        encryptor = Encryptors.stronger(properties.password(), properties.salt());
    }

    @Override
    public byte[] encrypt(final byte[] secret) {
        return encryptor.encrypt(secret);
    }

    @Override
    public byte[] decrypt(final byte[] encrypted) {
        try {
            return encryptor.decrypt(encrypted);
        } catch (final RuntimeException e) {
            throw new IllegalStateException("The TOTP secret cannot be decrypted", e);
        }
    }
}
