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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ApplePrivateKeyParser}. Every key is generated here at run time; none is committed.
 */
class ApplePrivateKeyParserTest {

    /** Size of an RSA key used to check that other key types are refused. */
    private static final int RSA_BITS = 2048;

    /** Length of the lines of a PEM body. */
    private static final int PEM_LINE_LENGTH = 64;

    /** Parser under test. */
    private final ApplePrivateKeyParser parser = new ApplePrivateKeyParser();

    /**
     * Verifies that a PEM key with its header and footer lines is read.
     *
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    @Test
    void parse_whenPemHasHeaderAndFooter_returnsTheKey() throws GeneralSecurityException {
        final var pair = generate("secp256r1");

        final var key = parser.parse(pem(pair, "\n"));

        assertEquals(pair.getPrivate(), key);
    }

    /**
     * Verifies that a key whose line breaks an environment variable holds as a literal {@code \n} is read, and so is a
     * bare Base64 body.
     *
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    @Test
    void parse_whenLineBreaksAreLiteralOrAbsent_returnsTheKey() throws GeneralSecurityException {
        final var pair = generate("secp256r1");
        final var body = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        assertEquals(pair.getPrivate(), parser.parse(pem(pair, "\\n")));
        assertEquals(pair.getPrivate(), parser.parse(body));
    }

    /**
     * Verifies that a key of another curve is refused.
     *
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    @Test
    void parse_whenCurveIsNotP256_throwsIllegalArgumentException() throws GeneralSecurityException {
        final var pem = pem(generate("secp384r1"), "\n");

        assertThrows(IllegalArgumentException.class, () -> parser.parse(pem));
    }

    /**
     * Verifies that a key that is not an EC key is refused.
     *
     * @throws GeneralSecurityException if the key cannot be generated.
     */
    @Test
    void parse_whenKeyIsNotEc_throwsIllegalArgumentException() throws GeneralSecurityException {
        final var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_BITS);
        final var pem = pem(generator.generateKeyPair(), "\n");

        assertThrows(IllegalArgumentException.class, () -> parser.parse(pem));
    }

    /**
     * Verifies that text that is not a key is refused, and that the message never repeats it.
     */
    @Test
    void parse_whenTextIsNotAKey_throwsIllegalArgumentExceptionWithoutRepeatingIt() {
        final var secretText = "definitely-not-base64-%%%";

        final var error = assertThrows(IllegalArgumentException.class, () -> parser.parse(secretText));

        assertFalse(error.getMessage().contains(secretText));
        assertTrue(error.getMessage().contains("private-key"));
    }

    /**
     * Generates an EC key pair.
     *
     * @param curve name of the curve.
     * @return the pair.
     * @throws GeneralSecurityException if it cannot be generated.
     */
    private static KeyPair generate(final String curve) throws GeneralSecurityException {
        final var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    /**
     * Writes a private key as PEM.
     *
     * @param pair      the pair.
     * @param lineBreak text used as a line break.
     * @return the PEM text.
     */
    private static String pem(final KeyPair pair, final String lineBreak) {
        final var body = Base64.getMimeEncoder(PEM_LINE_LENGTH, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(pair.getPrivate().getEncoded()).replace("\n", lineBreak);
        return "-----BEGIN PRIVATE KEY-----" + lineBreak + body + lineBreak + "-----END PRIVATE KEY-----";
    }
}
