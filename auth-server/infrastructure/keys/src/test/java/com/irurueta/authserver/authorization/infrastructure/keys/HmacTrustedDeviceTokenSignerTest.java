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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests of {@link HmacTrustedDeviceTokenSigner}, with a secret generated at run time.
 */
class HmacTrustedDeviceTokenSignerTest {

    /** Properties shared by the signer under test. */
    private final KeyEncryptionProperties properties = KeyTestSupport.randomProperties();

    /** Signer under test. */
    private final HmacTrustedDeviceTokenSigner signer =
            new HmacTrustedDeviceTokenSigner(new PurposeKeyDerivation(properties));

    /** A raw token. */
    private final String token = UUID.randomUUID().toString().replace("-", "");

    /**
     * Verifies that a signed value has the form token, dot, signature, and verifies back to the token.
     */
    @Test
    void verify_whenValueWasSigned_returnsTheToken() {
        final var signed = signer.sign(token);

        assertTrue(signed.startsWith(token + "."));
        assertEquals(token, signer.verify(signed).orElseThrow());
    }

    /**
     * Verifies that an unsigned token is rejected.
     */
    @Test
    void verify_whenValueIsUnsigned_returnsEmpty() {
        assertTrue(signer.verify(token).isEmpty());
    }

    /**
     * Verifies that a value whose token was changed is rejected.
     */
    @Test
    void verify_whenTokenIsAltered_returnsEmpty() {
        final var signed = signer.sign(token);
        final var signature = signed.substring(signed.lastIndexOf('.'));

        assertTrue(signer.verify("x" + token + signature).isEmpty());
    }

    /**
     * Verifies that a forged signature of the right length is rejected.
     */
    @Test
    void verify_whenSignatureIsForged_returnsEmpty() {
        final var signed = signer.sign(token);
        final var length = Base64.getUrlDecoder().decode(signed.substring(signed.lastIndexOf('.') + 1)).length;
        final var forged = token + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[length]);

        assertTrue(signer.verify(forged).isEmpty());
    }

    /**
     * Verifies that a value signed with another secret is rejected.
     */
    @Test
    void verify_whenSignedWithAnotherSecret_returnsEmpty() {
        final var other = new HmacTrustedDeviceTokenSigner(new PurposeKeyDerivation(KeyTestSupport.randomProperties()));

        assertNotEquals(signer.sign(token), other.sign(token));
        assertTrue(signer.verify(other.sign(token)).isEmpty());
    }

    /**
     * Verifies that missing, blank and malformed values are rejected without failing.
     *
     * @param value the value presented.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", ".", ".signature", "token.", "token.!!not-base64!!"})
    void verify_whenValueIsMalformed_returnsEmpty(final String value) {
        assertTrue(signer.verify(value).isEmpty());
    }
}
