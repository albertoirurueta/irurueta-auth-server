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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Keys generated at run time for the tests: nothing is ever committed.
 */
final class TestKeys {

    /** Size of the generated RSA keys. */
    private static final int RSA_BITS = 2048;

    /** Length of the lines of a PEM body. */
    private static final int PEM_LINE_LENGTH = 64;

    /**
     * Not instantiable: static helpers only.
     */
    private TestKeys() {
        // no instance is ever created
    }

    /**
     * Generates an RSA key pair.
     *
     * @return the key pair.
     */
    static KeyPair rsaKeyPair() {
        try {
            final var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(RSA_BITS);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Writes the private key of a pair as an unencrypted PKCS#8 PEM.
     *
     * @param pair the key pair.
     * @return the PEM text, with {@code \n} line ends.
     */
    static String pkcs8Pem(final KeyPair pair) {
        final var body = Base64.getMimeEncoder(PEM_LINE_LENGTH, new byte[] {'\n'})
                .encodeToString(pair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }
}
