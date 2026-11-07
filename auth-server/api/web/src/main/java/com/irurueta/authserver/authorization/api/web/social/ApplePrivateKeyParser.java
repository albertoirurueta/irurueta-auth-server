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

package com.irurueta.authserver.authorization.api.web.social;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * Reads the private key Apple issues for Sign in with Apple (an EC P-256 key in PKCS#8 PEM form, the content of the
 * {@code .p8} file) from the text an environment variable holds, where line breaks are often written as a literal
 * {@code \n}. The error never repeats the key.
 */
@Component
public class ApplePrivateKeyParser {

    /** Bits of the order of the P-256 curve Apple's ES256 keys use. */
    static final int P256_ORDER_BITS = 256;

    /**
     * Parses a key.
     *
     * @param pem PKCS#8 PEM text of the key, with or without the header and footer lines.
     * @return the private key.
     * @throws IllegalArgumentException if the text is not a PKCS#8 EC P-256 private key.
     */
    public ECPrivateKey parse(final String pem) {
        final var body = pem.replace("\\n", "\n")
                .replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        try {
            final var key = KeyFactory.getInstance("EC")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            if (key instanceof final ECPrivateKey ecKey
                    && ecKey.getParams().getOrder().bitLength() == P256_ORDER_BITS) {
                return ecKey;
            }
        } catch (final GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalArgumentException(notAKey(), e);
        }
        throw new IllegalArgumentException(notAKey());
    }

    /**
     * Builds the message of a refused key.
     *
     * @return the message.
     */
    private static String notAKey() {
        return "authserver.social.providers.apple.private-key is not a PKCS#8 EC P-256 private key";
    }
}
