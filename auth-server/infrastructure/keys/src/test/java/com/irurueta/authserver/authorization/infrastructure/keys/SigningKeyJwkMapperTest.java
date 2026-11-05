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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.nimbusds.jose.jwk.JWK;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link SigningKeyJwkMapper}.
 */
@ExtendWith(MockitoExtension.class)
class SigningKeyJwkMapperTest {

    /** Instant the keys are created and activated at. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Text that is not a JSON Web Key. */
    private static final String NOT_A_JWK = "{}";

    /** Ciphertext the mocked cipher decrypts; not a real secret. */
    private static final String ENCRYPTED = "encrypted";

    /** Decrypts the private half; mocked so the test controls the plaintext. */
    @Mock
    private AesGcmKeyCipher cipher;

    /** Mapper under test. */
    @InjectMocks
    private SigningKeyJwkMapper mapper;

    /** An active key, generated with a real cipher. */
    private SigningKey active;

    /** The plaintext private JWK of {@link #active}. */
    private String privateJwk;

    /**
     * Generates an active key and records its decrypted private half.
     */
    @BeforeEach
    void setUp() {
        final var realCipher = new AesGcmKeyCipher(KeyTestSupport.randomProperties());
        active = new RsaSigningKeyGenerator(realCipher).generate(NOW).activate(NOW);
        privateJwk = realCipher.decrypt(active.encryptedPrivateJwk());
    }

    /**
     * Verifies that every key is published with its public half only, in the given order.
     */
    @Test
    void toPublicJwkSet_whenKeysAreGiven_returnsPublicHalves() {
        final var other = new RsaSigningKeyGenerator(new AesGcmKeyCipher(KeyTestSupport.randomProperties()))
                .generate(NOW);

        final var set = mapper.toPublicJwkSet(List.of(active, other));

        assertEquals(List.of(active.kid(), other.kid()), set.getKeys().stream().map(JWK::getKeyID).toList());
        assertTrue(set.getKeys().stream().noneMatch(JWK::isPrivate));
    }

    /**
     * Verifies that no keys give an empty public set.
     */
    @Test
    void toPublicJwkSet_whenNoKeysAreGiven_returnsEmptySet() {
        assertTrue(mapper.toPublicJwkSet(List.of()).getKeys().isEmpty());
    }

    /**
     * Verifies that a published key that is not a JWK is reported.
     */
    @Test
    void toPublicJwkSet_whenStoredKeyIsNotAJwk_throwsIllegalStateException() {
        final var broken = new SigningKey(active.kid(), active.alg(), NOT_A_JWK, active.encryptedPrivateJwk(),
                active.status(), NOW, NOW, null);
        final var keys = List.of(broken);

        assertThrows(IllegalStateException.class, () -> mapper.toPublicJwkSet(keys));
    }

    /**
     * Verifies that the active key is decrypted and kept with its private half.
     */
    @Test
    void toSigningJwkSet_whenActiveKeyExists_returnsItsPrivateHalf() {
        final var key = new SigningKey(active.kid(), active.alg(), active.publicJwk(), ENCRYPTED, active.status(),
                NOW, NOW, null);
        when(cipher.decrypt(ENCRYPTED)).thenReturn(privateJwk);

        final var set = mapper.toSigningJwkSet(Optional.of(key));

        verify(cipher).decrypt(ENCRYPTED);
        assertEquals(1, set.getKeys().size());
        assertEquals(active.kid(), set.getKeys().getFirst().getKeyID());
        assertTrue(set.getKeys().getFirst().isPrivate());
    }

    /**
     * Verifies that there is nothing to sign with before the first rotation.
     */
    @Test
    void toSigningJwkSet_whenThereIsNoActiveKey_returnsEmptySet() {
        assertTrue(mapper.toSigningJwkSet(Optional.empty()).getKeys().isEmpty());
    }

    /**
     * Verifies that a decrypted private half that is not a JWK is reported.
     */
    @Test
    void toSigningJwkSet_whenDecryptedKeyIsNotAJwk_throwsIllegalStateException() {
        when(cipher.decrypt(active.encryptedPrivateJwk())).thenReturn(NOT_A_JWK);
        final var key = Optional.of(active);

        assertThrows(IllegalStateException.class, () -> mapper.toSigningJwkSet(key));
    }

    /**
     * Verifies that a valid key is parsed.
     */
    @Test
    void toJwk_whenJsonIsAValidKey_returnsKey() {
        final var jwk = mapper.toJwk(active.publicJwk());

        assertEquals(active.kid(), jwk.getKeyID());
        assertFalse(jwk.isPrivate());
    }

    /**
     * Verifies that invalid JSON is reported, keeping the parse failure as its cause.
     */
    @Test
    void toJwk_whenJsonIsNotAKey_throwsIllegalStateException() {
        final var error = assertThrows(IllegalStateException.class, () -> mapper.toJwk(NOT_A_JWK));

        assertInstanceOf(ParseException.class, error.getCause());
    }
}
