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
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

// tag::keys-purpose-derivation[]
/**
 * Derives, from the key-encryption secret ({@link KeyEncryptionProperties}), a distinct salt and key for each purpose
 * other than the encryption of signing keys, so no two uses share a key: a key exposed or misused for one purpose
 * says nothing about the others. The salt of a purpose is the HMAC-SHA256 of the purpose label keyed with the
 * configured salt; its key is derived from the passphrase and that salt with PBKDF2-HMAC-SHA256. The signing-key
 * cipher ({@link AesGcmKeyCipher}) keeps using the configured salt itself, so the keys already stored still decrypt.
 */
@Component
@RequiredArgsConstructor
public class PurposeKeyDerivation {

    /** Algorithm that derives the salt of a purpose. */
    private static final String SALT_ALGORITHM = "HmacSHA256";

    /** Algorithm that derives the key of a purpose. */
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA256";

    /** PBKDF2 iterations; a key is derived once per purpose, when its bean is created. */
    private static final int ITERATIONS = 100_000;

    /** Size of a derived key in bits (AES-256 / HMAC-SHA256). */
    private static final int KEY_BITS = 256;

    /** The passphrase and the salt of the key-encryption secret. */
    private final KeyEncryptionProperties properties;

    /**
     * Derives the salt of a purpose.
     *
     * @param purpose label of the purpose, for example {@code totp-secret}.
     * @return the salt, hex encoded, as {@code Encryptors.stronger} expects it.
     */
    public String saltFor(final String purpose) {
        try {
            final var mac = Mac.getInstance(SALT_ALGORITHM);
            mac.init(new SecretKeySpec(properties.salt().getBytes(StandardCharsets.UTF_8), SALT_ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(purpose.getBytes(StandardCharsets.UTF_8)));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("The salt of " + purpose + " cannot be derived", e);
        }
    }

    /**
     * Derives the key of a purpose.
     *
     * @param purpose label of the purpose, for example {@code trusted-device-cookie}.
     * @return the 256-bit key.
     */
    public byte[] keyFor(final String purpose) {
        final var spec = new PBEKeySpec(properties.password().toCharArray(),
                HexFormat.of().parseHex(saltFor(purpose)), ITERATIONS, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(KEY_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("The key of " + purpose + " cannot be derived", e);
        } finally {
            spec.clearPassword();
        }
    }
}
// end::keys-purpose-derivation[]
